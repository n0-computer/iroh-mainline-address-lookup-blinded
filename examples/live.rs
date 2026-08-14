//! Publish and resolve a blinded record on the real mainline DHT.
//!
//! Publish (keeps running, republishing hourly):
//!   cargo run --example live -- publish
//! Resolve, from any other machine, using the endpoint id printed by publish:
//!   cargo run --example live -- resolve <endpoint-id>

use clap::Parser;
use iroh::{
    EndpointId, SecretKey,
    address_lookup::{AddressLookup, EndpointData},
};
use iroh_mainline_address_lookup_blinded::BlindedLookup;
use n0_future::StreamExt;

#[derive(Parser)]
enum Command {
    /// Publish a demo record under a blinded key derived from a random secret.
    Publish,
    /// Resolve the record for the given endpoint id.
    Resolve { endpoint_id: EndpointId },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    match Command::parse() {
        Command::Publish => {
            let secret = SecretKey::generate();
            println!("endpoint id: {}", secret.public());
            let lookup = BlindedLookup::builder().build_with_secret_key(&secret)?;
            let mut data = EndpointData::new(vec![]);
            data.add_relay_url("https://euw1-1.relay.n0.iroh-canary.iroh.link./".parse()?);
            lookup.publish(&data);
            println!("publishing (ctrl-c to stop) ...");
            tokio::signal::ctrl_c().await?;
        }
        Command::Resolve { endpoint_id } => {
            let lookup = BlindedLookup::builder().build()?;
            let mut stream = lookup.resolve(endpoint_id).expect("resolve stream");
            match stream.next().await {
                Some(Ok(item)) => {
                    println!("resolved: {:?}", item.endpoint_info());
                }
                other => println!("not found: {other:?}"),
            }
        }
    }
    Ok(())
}
