mod support;

use std::time::Duration;

use rns_protocol::channel_message::{MessageBase, SMT_STREAM_DATA};
use rns_protocol::stream_data::StreamDataMessage;
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
            message = destination.events.channel_messages.recv() => {
                let Some(message) = message else { break };
                if message.msg_type != SMT_STREAM_DATA {
                    continue;
                }
                let mut frame = StreamDataMessage::new(0, Vec::new(), false);
                frame.unpack(&message.payload)?;
                if frame.eof {
                    destination
                        .handle
                        .send_channel(
                            message.link_id,
                            SMT_STREAM_DATA,
                            StreamDataMessage::new(frame.stream_id, Vec::new(), true).pack(),
                        )
                        .await?;
                    continue;
                }

                let text = String::from_utf8_lossy(&frame.data);
                println!("Received over Buffer: {text}");
                let reply = StreamDataMessage::new(
                    frame.stream_id,
                    format!("Received: {text}").into_bytes(),
                    false,
                );
                destination
                    .handle
                    .send_channel(message.link_id, SMT_STREAM_DATA, reply.pack())
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
