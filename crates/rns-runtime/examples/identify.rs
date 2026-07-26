mod support;

use rns_runtime::prelude::*;
use support::*;

const ASPECT: &str = "example_utilities.identifyexample";

#[tokio::main]
async fn main() -> ExampleResult {
    let args = ExampleArgs::parse()?;
    match args.require(0, "mode: server | client")? {
        "server" => server(args).await,
        "client" => client(args).await,
        other => Err(format!("unknown mode {other}; use server or client").into()),
    }
}

async fn server(args: ExampleArgs) -> ExampleResult {
    let runtime = ExampleRuntime::start(args.config_dir.as_deref()).await?;
    let mut destination = register_single(
        &runtime.handle,
        Identity::new(),
        ASPECT,
        DestinationRuntimeOptions::default(),
    )
    .await?;
    print_destination(
        "Identification destination",
        destination.handle.destination_hash(),
    );
    destination
        .handle
        .announce(DestinationAnnounceOptions::default())
        .await?;

    loop {
        tokio::select! {
            _ = runtime.shutdown.wait() => break,
            established = destination.events.links_established.recv() => {
                let Some(link_id) = established else { break };
                println!("Link {} established", hex::encode(link_id));
            }
            identified = destination.events.links_identified.recv() => {
                let Some((link_id, identity_hash)) = identified else { break };
                println!(
                    "Link {} identified as {}",
                    hex::encode(link_id),
                    hex::encode(identity_hash),
                );
            }
        }
    }

    destination.close().await?;
    runtime.stop().await;
    Ok(())
}

async fn client(args: ExampleArgs) -> ExampleResult {
    let destination_hash = parse_destination_hash(args.require(1, "destination hash")?)?;
    let runtime = ExampleRuntime::start(args.config_dir.as_deref()).await?;
    let session = connect(&runtime.handle, destination_hash, true, "identify-example").await?;
    println!(
        "Established and identified Link {}",
        hex::encode(session.handle.link_id())
    );
    session.handle.close().await;
    runtime.stop().await;
    Ok(())
}
