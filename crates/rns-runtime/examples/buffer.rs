mod support;

use std::time::Duration;

use rns_runtime::prelude::*;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ASPECT: &str = "example_utilities.bufferexample";
const STREAM_ID: u16 = 0;

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
    print_destination("Buffer destination", destination.handle.destination_hash());
    destination
        .handle
        .announce(DestinationAnnounceOptions::default())
        .await?;

    loop {
        tokio::select! {
            _ = runtime.shutdown.wait() => break,
            link_id = destination.events.links_established.recv() => {
                let Some(link_id) = link_id else { break };
                // Open the stream as soon as the link is up, as a Python server would.
                let mut buffer = destination
                    .handle
                    .create_bidirectional_buffer(link_id, STREAM_ID, STREAM_ID)
                    .await?;
                tokio::spawn(async move {
                    let mut data = vec![0; 4096];
                    while let Ok(n) = buffer.read(&mut data).await {
                        if n == 0 {
                            break;
                        }
                        let text = String::from_utf8_lossy(&data[..n]).into_owned();
                        println!("Received over Buffer: {text}");
                        let reply = format!("Received: {text}");
                        if buffer.write_all(reply.as_bytes()).await.is_err()
                            || buffer.flush().await.is_err()
                        {
                            break;
                        }
                    }
                    let _ = buffer.shutdown().await;
                });
            }
        }
    }

    destination.close().await?;
    runtime.stop().await;
    Ok(())
}

async fn client(args: ExampleArgs) -> ExampleResult {
    let destination_hash = parse_destination_hash(args.require(1, "destination hash")?)?;
    let message = args
        .positional
        .get(2)
        .map_or("Hello Buffer", String::as_str);
    let runtime = ExampleRuntime::start(args.config_dir.as_deref()).await?;
    let session = connect(&runtime.handle, destination_hash, false, "buffer-example").await?;
    let mut buffer = session
        .handle
        .channel()
        .create_bidirectional_buffer(STREAM_ID, STREAM_ID)
        .await?;

    buffer.write_all(message.as_bytes()).await?;
    buffer.flush().await?;
    let expected_len = "Received: ".len() + message.len();
    let mut reply = vec![0; expected_len];
    tokio::time::timeout(Duration::from_secs(30), buffer.read_exact(&mut reply)).await??;
    println!("Reply: {}", String::from_utf8_lossy(&reply));
    buffer.shutdown().await?;

    session.handle.close().await;
    runtime.stop().await;
    Ok(())
}
