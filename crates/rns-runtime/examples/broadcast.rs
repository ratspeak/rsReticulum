mod support;

use rns_runtime::prelude::*;
use support::*;

const ASPECT: &str = "example_utilities.broadcast";

#[tokio::main]
async fn main() -> ExampleResult {
    let args = ExampleArgs::parse()?;
    let message = args
        .positional
        .first()
        .map_or("Hello Reticulum", String::as_str);
    let runtime = ExampleRuntime::start(args.config_dir.as_deref()).await?;
    let destination = Destination::new(None, Direction::Out, DestType::Plain, ASPECT)?;

    let sent = runtime
        .handle
        .send_to(
            &destination,
            message.as_bytes(),
            SendOptions {
                create_receipt: false,
                ..SendOptions::default()
            },
        )
        .await?;
    println!(
        "Broadcast {} to {}",
        hex::encode(sent.packet_hash),
        hex::encode(destination.hash)
    );

    runtime.stop().await;
    Ok(())
}
