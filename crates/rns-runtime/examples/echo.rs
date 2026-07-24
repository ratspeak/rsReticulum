mod support;

use rns_runtime::prelude::*;
use support::*;

const ASPECT: &str = "example_utilities.echo";

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
        DestinationRuntimeOptions {
            proof_strategy: ProofStrategy::ProveAll,
            ..DestinationRuntimeOptions::default()
        },
    )
    .await?;
    print_destination("Echo destination", destination.handle.destination_hash());
    destination
        .handle
        .announce(DestinationAnnounceOptions::default())
        .await?;

    loop {
        tokio::select! {
            _ = runtime.shutdown.wait() => break,
            packet = destination.events.packets.recv() => {
                let Some(packet) = packet else { break };
                println!("Proved {} bytes: {}", packet.data.len(), String::from_utf8_lossy(&packet.data));
            }
        }
    }
    destination.close().await?;
    runtime.stop().await;
    Ok(())
}

async fn client(args: ExampleArgs) -> ExampleResult {
    let destination_hash = parse_destination_hash(args.require(1, "destination hash")?)?;
    let message = args.positional.get(2).map_or("Hello echo", String::as_str);
    let runtime = ExampleRuntime::start(args.config_dir.as_deref()).await?;
    let destination =
        recall_outbound_destination(&runtime.handle, destination_hash, ASPECT).await?;
    let sent = runtime
        .handle
        .send_to(&destination, message.as_bytes(), SendOptions::default())
        .await?;
    let receipt = sent.receipt.ok_or("echo send did not create a receipt")?;
    let rtt = receipt.delivered().await?;
    println!("Delivered in {:.3} ms", rtt.as_secs_f64() * 1000.0);
    runtime.stop().await;
    Ok(())
}
