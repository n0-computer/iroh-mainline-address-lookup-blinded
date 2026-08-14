//! POC address lookup for iroh that publishes to the BitTorrent mainline DHT
//! under a *blinded* key instead of the endpoint's public key.
//!
//! The published record is a postcard-encoded blob (no DNS packet, no pkarr),
//! sealed with a key derived from the master public key and padded to a fixed
//! size, stored as a BEP44 mutable item. DHT nodes verify the item's ed25519
//! signature against the blinded key like any other; they never see the
//! endpoint id. Resolvers that know an endpoint id derive the same blinded key
//! and payload key; DHT crawlers see only unlinkable pseudonyms holding opaque,
//! uniformly sized blobs.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use iroh::{
    Endpoint, EndpointId, RelayUrl, SecretKey, TransportAddr,
    address_lookup::{
        AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, EndpointData, EndpointInfo,
        Error, Item, UserData,
    },
};
use n0_future::boxed::BoxStream;
use n0_mainline::{Dht, MutableItem};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, warn};

pub mod blinding;
pub mod encryption;

use blinding::{BlindedKeypair, blind_public_key};

/// Provenance string for items produced by this lookup.
pub const PROVENANCE: &str = "blinded-mainline";

/// Default blinding context. This is a wire-format constant: all publishers and
/// resolvers must agree on it, and changing it re-keys every pseudonym.
pub const DEFAULT_CONTEXT: &[u8] = b"iroh-blinded-lookup/v1";

/// Default interval for republishing to the DHT (mainline nodes drop mutable
/// items after a couple of hours).
pub const DEFAULT_REPUBLISH_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Length of a blinding time period, matching Tor v3 onion services' default.
pub const TIME_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

/// Offset from the Unix epoch: periods rotate at 12:00 UTC, as in Tor v3.
const TIME_PERIOD_OFFSET: Duration = Duration::from_secs(12 * 60 * 60);

fn time_period(now: SystemTime) -> u64 {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_secs();
    seconds.saturating_sub(TIME_PERIOD_OFFSET.as_secs()) / TIME_PERIOD.as_secs()
}

fn period_context(context: &[u8], period: u64) -> Vec<u8> {
    let mut result = Vec::with_capacity(context.len() + 8);
    result.extend_from_slice(context);
    result.extend_from_slice(&period.to_be_bytes());
    result
}

/// The postcard wire format of the published record.
///
/// Deliberately independent of iroh's `EndpointData` so the wire format stays
/// stable under iroh refactors. Custom transport addresses are not supported.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Wire {
    V1(WireData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireData {
    relay_urls: Vec<String>,
    ip_addrs: Vec<SocketAddr>,
    user_data: Option<String>,
}

impl WireData {
    fn from_endpoint_data(data: &EndpointData) -> Self {
        Self {
            relay_urls: data.relay_urls().map(|url| url.to_string()).collect(),
            ip_addrs: data.ip_addrs().copied().collect(),
            user_data: data.user_data().map(|d| d.to_string()),
        }
    }

    fn into_endpoint_data(self) -> Result<EndpointData, LookupError> {
        let mut addrs = Vec::new();
        for url in self.relay_urls {
            let url: RelayUrl = url
                .parse()
                .map_err(|_| LookupError::BadRecord("invalid relay url"))?;
            addrs.push(TransportAddr::Relay(url));
        }
        addrs.extend(self.ip_addrs.into_iter().map(TransportAddr::Ip));
        let mut data = EndpointData::new(addrs);
        if let Some(user_data) = self.user_data {
            let user_data = UserData::try_from(user_data)
                .map_err(|_| LookupError::BadRecord("invalid user data"))?;
            data.set_user_data(Some(user_data));
        }
        Ok(data)
    }
}

/// The BEP44 signable encoding of a mutable item without salt, byte-identical
/// to n0-mainline's (not re-exported) `encode_signable`.
fn encode_signable(seq: i64, value: &[u8]) -> Vec<u8> {
    let mut signable = format!("3:seqi{}e1:v{}:", seq, value.len()).into_bytes();
    signable.extend(value);
    signable
}

/// Errors produced by [`BlindedLookup`].
#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    #[error("dht actor shut down")]
    Shutdown,
    #[error("no record found")]
    NotFound,
    #[error("failed to decode record: {0}")]
    Decode(#[from] postcard::Error),
    #[error("bad record: {0}")]
    BadRecord(&'static str),
}

/// Builder for [`BlindedLookup`].
#[derive(Debug, Clone)]
pub struct Builder {
    bootstrap: Option<Vec<String>>,
    context: Vec<u8>,
    republish_interval: Duration,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            bootstrap: None,
            context: DEFAULT_CONTEXT.to_vec(),
            republish_interval: DEFAULT_REPUBLISH_INTERVAL,
        }
    }
}

impl Builder {
    /// Overrides the DHT bootstrap nodes (e.g. for a testnet).
    pub fn bootstrap(mut self, bootstrap: Vec<String>) -> Self {
        self.bootstrap = Some(bootstrap);
        self
    }

    /// Overrides the blinding context.
    pub fn context(mut self, context: impl Into<Vec<u8>>) -> Self {
        self.context = context.into();
        self
    }

    /// Overrides the republish interval.
    pub fn republish_interval(mut self, interval: Duration) -> Self {
        self.republish_interval = interval;
        self
    }

    fn dht(&self) -> std::io::Result<Dht> {
        let mut builder = Dht::builder();
        if let Some(bootstrap) = &self.bootstrap {
            builder.bootstrap(bootstrap);
        }
        builder.build()
    }

    /// Builds a resolve-only lookup.
    pub fn build(self) -> std::io::Result<BlindedLookup> {
        let dht = self.dht()?;
        Ok(BlindedLookup {
            dht,
            context: Arc::new(self.context),
            publisher: None,
        })
    }

    /// Builds a lookup that also publishes, signing under the blinded key
    /// derived from `secret_key`.
    ///
    /// Must be called from within a tokio runtime.
    pub fn build_with_secret_key(self, secret_key: &SecretKey) -> std::io::Result<BlindedLookup> {
        let dht = self.dht()?;
        let publisher = Arc::new(PublisherKeys {
            master_sk: secret_key.to_bytes(),
            master_pk: *secret_key.public().as_bytes(),
            context: self.context.clone(),
        });
        let (tx, rx) = watch::channel(None);
        let task = tokio::spawn(publish_task(
            dht.clone(),
            publisher,
            rx,
            self.republish_interval,
        ));
        Ok(BlindedLookup {
            dht,
            context: Arc::new(self.context),
            publisher: Some(PublisherHandle {
                tx,
                task: Arc::new(AbortOnDrop(task)),
            }),
        })
    }
}

/// Implementing [`AddressLookupBuilder`] lets the builder be handed directly to
/// `Endpoint::builder().address_lookup(...)`, picking up the endpoint's secret
/// key for publishing.
impl AddressLookupBuilder for Builder {
    fn into_address_lookup(
        self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        self.build_with_secret_key(endpoint.secret_key())
            .map_err(|err| AddressLookupBuilderError::from_err(PROVENANCE, err))
    }
}

#[derive(Debug)]
struct PublisherKeys {
    master_sk: [u8; 32],
    master_pk: [u8; 32],
    context: Vec<u8>,
}

#[derive(Debug)]
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Debug, Clone)]
struct PublisherHandle {
    tx: watch::Sender<Option<EndpointData>>,
    task: Arc<AbortOnDrop>,
}

/// An [`AddressLookup`] that stores postcard-encoded endpoint data as BEP44
/// mutable items on the mainline DHT, keyed by a blinded endpoint key.
#[derive(Debug, Clone)]
pub struct BlindedLookup {
    dht: Dht,
    context: Arc<Vec<u8>>,
    publisher: Option<PublisherHandle>,
}

impl BlindedLookup {
    /// Returns a builder.
    pub fn builder() -> Builder {
        Builder::default()
    }
}

async fn publish_task(
    dht: Dht,
    publisher: Arc<PublisherKeys>,
    mut rx: watch::Receiver<Option<EndpointData>>,
    republish_interval: Duration,
) {
    if dht.bootstrapped().await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            _ = tokio::time::sleep(republish_interval) => {}
        }
        let Some(data) = rx.borrow_and_update().clone() else {
            continue;
        };
        let wire = Wire::V1(WireData::from_endpoint_data(&data));
        let plaintext = match postcard::to_stdvec(&wire) {
            Ok(value) => value,
            Err(err) => {
                warn!("failed to encode endpoint data: {err:#}");
                continue;
            }
        };
        let now = SystemTime::now();
        let period = time_period(now);
        let seq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before unix epoch")
            .as_secs() as i64;

        // Like Tor v3 onion services, keep two consecutive time periods active.
        // Publishing the next period early lets clients on either side of a
        // period boundary find us despite clock disagreement.
        for period in [period, period + 1] {
            let context = period_context(&publisher.context, period);
            let secret = SecretKey::from_bytes(&publisher.master_sk);
            let keypair = BlindedKeypair::from_master(&secret, &context);
            let value = encryption::seal(&publisher.master_pk, &context, &plaintext);
            let signable = encode_signable(seq, &value);
            let signature = keypair.sign(&signable);
            let item = MutableItem::new_signed_unchecked(
                keypair.public_bytes(),
                signature.to_bytes(),
                &value,
                seq,
                None,
            );
            match dht.put_mutable(item, None).await {
                Ok(target) => debug!(period, "published blinded record at {target}"),
                Err(err) => warn!(period, "failed to publish blinded record: {err:#}"),
            }
        }
    }
}

impl AddressLookup for BlindedLookup {
    fn publish(&self, data: &EndpointData) {
        if let Some(publisher) = &self.publisher {
            // Keep the task alive as long as the lookup exists.
            let _task = &publisher.task;
            publisher.tx.send_replace(Some(data.clone()));
        }
    }

    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        let dht = self.dht.clone();
        let context = self.context.clone();
        let fut = async move {
            let period = time_period(SystemTime::now());
            let mut found = None;
            for period in [period, period + 1] {
                let period_context = period_context(&context, period);
                let blinded = blind_public_key(endpoint_id.as_bytes(), &period_context)
                    .map_err(|err| Error::from_err(PROVENANCE, err))?;
                let item = dht
                    .get_mutable_most_recent(&blinded, None)
                    .await
                    .map_err(|_| Error::from_err(PROVENANCE, LookupError::Shutdown))?;
                if let Some(item) = item {
                    found = Some((item, period_context));
                    break;
                }
            }
            let (item, period_context) =
                found.ok_or_else(|| Error::from_err(PROVENANCE, LookupError::NotFound))?;
            let plaintext = encryption::open(endpoint_id.as_bytes(), &period_context, item.value())
                .map_err(|err| Error::from_err(PROVENANCE, err))?;
            let wire: Wire = postcard::from_bytes(&plaintext)
                .map_err(|err| Error::from_err(PROVENANCE, LookupError::from(err)))?;
            let Wire::V1(wire) = wire;
            let data = wire
                .into_endpoint_data()
                .map_err(|err| Error::from_err(PROVENANCE, err))?;
            let info = EndpointInfo::from_parts(endpoint_id, data);
            let last_updated = u64::try_from(item.seq()).ok().map(|secs| secs * 1_000_000);
            Ok(Item::new(info, PROVENANCE, last_updated))
        };
        Some(Box::pin(n0_future::stream::once_future(fut)))
    }
}

#[cfg(test)]
mod time_tests {
    use super::*;

    #[test]
    fn periods_rotate_daily_at_noon_utc() {
        let before_noon = UNIX_EPOCH + Duration::from_secs(36 * 60 * 60 - 1);
        let at_noon = UNIX_EPOCH + Duration::from_secs(36 * 60 * 60);
        assert_eq!(time_period(before_noon), 0);
        assert_eq!(time_period(at_noon), 1);
        assert_ne!(
            period_context(DEFAULT_CONTEXT, 0),
            period_context(DEFAULT_CONTEXT, 1)
        );
    }
}
