mod support;

use std::time::Duration;

use rns_runtime::prelude::*;
use support::*;

const ASPECT: &str = "example_utilities.linkexample";

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
    print_destination("Link destination", destination.handle.destination_hash());
    destination
        .handle
        .announce(DestinationAnnounceOptions::default())
        .await?;

    loop {
        tokio::select! {
            _ = runtime.shutdown.wait() => break,
            packet = destination.events.link_packets.recv() => {
                let Some((data, link_id)) = packet else { break };
                println!("Received on {}: {}", hex::encode(link_id), String::from_utf8_lossy(&data));
                destination
                    .handle
                    .send_link_packet(link_id, data)
                    .await?;
            }
        }
    }

    destination.close().await?;
    runtime.stop().await;
    Ok(())
}

async fn client(args: ExampleArgs) -> ExampleResult {
    let destination_hash = parse_destination_hash(args.require(1, "destination hash")?)?;
    let message = args.positional.get(2).map_or("Hello Link", String::as_str);
    let runtime = ExampleRuntime::start(args.config_dir.as_deref()).await?;
    let mut session = connect(&runtime.handle, destination_hash, false, "link-example").await?;
    session
        .handle
        .send_packet(message.as_bytes().to_vec())
        .await?;

    let reply = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(event) = session.events.recv().await {
            if let LinkSessionEvent::Packet { data, .. } = event {
                return Some(data);
            }
        }
        None
    })
    .await?
    .ok_or("Link closed before the echo arrived")?;
    println!("Reply: {}", String::from_utf8_lossy(&reply));

    session.handle.close().await;
    runtime.stop().await;
    Ok(())
}
