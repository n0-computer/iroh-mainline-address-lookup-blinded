use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::{
    SecretKey,
    address_lookup::{AddressLookup, EndpointData},
};
use iroh_mainline_address_lookup_blinded::{
    BlindedLookup, DEFAULT_CONTEXT, TIME_PERIOD, blinding, encryption,
};
use n0_future::StreamExt;
use n0_mainline::{Dht, Testnet};

#[tokio::test]
async fn publish_resolve_roundtrip() {
    let testnet = Testnet::new(5).await.unwrap();

    let secret = SecretKey::from_bytes(&[42u8; 32]);
    let publisher = BlindedLookup::builder()
        .bootstrap(testnet.bootstrap.clone())
        .build_with_secret_key(&secret)
        .unwrap();

    let mut data = EndpointData::new(vec![]);
    data.add_relay_url("https://relay.example.com".parse().unwrap());
    data.add_ip_addrs(vec!["127.0.0.1:4433".parse().unwrap()]);
    publisher.publish(&data);

    let resolver = BlindedLookup::builder()
        .bootstrap(testnet.bootstrap.clone())
        .build()
        .unwrap();

    // The publish happens in a background task; poll until the record lands.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let mut stream = resolver.resolve(secret.public()).unwrap();
        match stream.next().await {
            Some(Ok(item)) => {
                assert_eq!(item.endpoint_id(), secret.public());
                let relays: Vec<_> = item.relay_urls().collect();
                assert_eq!(relays.len(), 1);
                assert_eq!(item.ip_addrs().count(), 1);
                assert_record_is_opaque(&testnet, &secret).await;
                return;
            }
            _ if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            other => panic!("record did not appear in time, last result: {other:?}"),
        }
    }
}

/// What a DHT crawler sees: a fixed-size blob that doesn't leak the contents.
async fn assert_record_is_opaque(testnet: &Testnet, secret: &SecretKey) {
    let mut builder = Dht::builder();
    builder.bootstrap(&testnet.bootstrap);
    let dht = builder.build().unwrap();
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let period = seconds.saturating_sub(12 * 60 * 60) / TIME_PERIOD.as_secs();
    let mut context = DEFAULT_CONTEXT.to_vec();
    context.extend_from_slice(&period.to_be_bytes());
    let blinded = blinding::blind_public_key(secret.public().as_bytes(), &context).unwrap();
    let item = dht
        .get_mutable_most_recent(&blinded, None)
        .await
        .unwrap()
        .expect("record exists");
    assert_eq!(item.value().len(), encryption::PAD_TO + 24 + 16);
    let needle = b"relay.example.com";
    assert!(
        !item
            .value()
            .windows(needle.len())
            .any(|window| window == needle)
    );
}
