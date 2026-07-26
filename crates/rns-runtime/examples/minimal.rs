mod support;

use rns_runtime::prelude::*;
use support::*;

const ASPECT: &str = "example_utilities.minimalsample";

#[tokio::main]
async fn main() -> ExampleResult {
    let args = ExampleArgs::parse()?;
    let runtime = ExampleRuntime::start(args.config_dir.as_deref()).await?;
    let mut destination = register_single(
        &runtime.handle,
        Identity::new(),
        ASPECT,
        DestinationRuntimeOptions {
            proof_strategy: ProofStrategy::ProveAll,
            ..DestinationRuntimeOptions::default()
        },
    )
    .await?;

    print_destination("Minimal destination", destination.handle.destination_hash());
    destination
        .handle
        .announce(DestinationAnnounceOptions::default())
        .await?;
    println!("Announced; waiting for packets (Ctrl-C to stop)");

    loop {
        tokio::select! {
            _ = runtime.shutdown.wait() => break,
            packet = destination.events.packets.recv() => {
                let Some(packet) = packet else { break };
                println!("Received: {}", String::from_utf8_lossy(&packet.data));
            }
        }
    }

    destination.close().await?;
    runtime.stop().await;
    Ok(())
}
