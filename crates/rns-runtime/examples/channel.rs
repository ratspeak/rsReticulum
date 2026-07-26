mod support;

use std::time::Duration;

use rns_runtime::prelude::*;
use support::*;

const ASPECT: &str = "example_utilities.channelexample";
const STRING_MESSAGE: u16 = 0x0101;

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
    print_destination("Channel destination", destination.handle.destination_hash());
    destination
        .handle
        .announce(DestinationAnnounceOptions::default())
        .await?;

    loop {
        tokio::select! {
            _ = runtime.shutdown.wait() => break,
            message = destination.events.channel_messages.recv() => {
                let Some(message) = message else { break };
                if message.msg_type == STRING_MESSAGE {
                    println!(
                        "Received on {}: {}",
                        hex::encode(message.link_id),
                        String::from_utf8_lossy(&message.payload),
                    );
                    destination
                        .handle
                        .send_channel(message.link_id, STRING_MESSAGE, message.payload)
                        .await?;
                }
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
        .map_or("Hello Channel", String::as_str);
    let runtime = ExampleRuntime::start(args.config_dir.as_deref()).await?;
    let session = connect(&runtime.handle, destination_hash, false, "channel-example").await?;
    let channel = session.handle.channel();
    channel.register_message_type(STRING_MESSAGE).await?;

    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel(1);
    let handler = channel
        .add_message_handler(move |msg_type, payload| {
            if msg_type != STRING_MESSAGE {
                return false;
            }
            let _ = reply_tx.try_send(payload.to_vec());
            true
        })
        .await?;
    channel.send_raw(STRING_MESSAGE, message.as_bytes()).await?;

    let reply = tokio::time::timeout(Duration::from_secs(30), reply_rx.recv())
        .await?
        .ok_or("Channel closed before the echo arrived")?;
    println!("Reply: {}", String::from_utf8_lossy(&reply));

    channel.remove_message_handler(handler).await?;
    session.handle.close().await;
    runtime.stop().await;
    Ok(())
}
