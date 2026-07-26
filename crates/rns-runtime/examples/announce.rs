mod support;

use rns_runtime::prelude::*;
use support::*;
use tokio::io::{AsyncBufReadExt, BufReader};

const ASPECT: &str = "example_utilities.announcesample.fruits";

#[tokio::main]
async fn main() -> ExampleResult {
    let args = ExampleArgs::parse()?;
    let runtime = ExampleRuntime::start(args.config_dir.as_deref()).await?;
    let mut subscription = runtime
        .handle
        .subscribe_announces(Some(ASPECT.to_string()), false)
        .await?;
    let destination = register_single(
        &runtime.handle,
        Identity::new(),
        ASPECT,
        DestinationRuntimeOptions::default(),
    )
    .await?;
    print_destination(
        "Announce destination",
        destination.handle.destination_hash(),
    );
    println!("Press enter to announce with app data; Ctrl-C stops");

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            _ = runtime.shutdown.wait() => break,
            announce = subscription.recv() => {
                let Some(announce) = announce else { break };
                println!(
                    "Observed {} app_data={}",
                    hex::encode(announce.destination_hash),
                    announce
                        .app_data
                        .as_deref()
                        .map(String::from_utf8_lossy)
                        .unwrap_or_default(),
                );
            }
            line = lines.next_line() => {
                if line?.is_none() {
                    break;
                }
                destination
                    .handle
                    .announce(DestinationAnnounceOptions {
                        app_data: Some(b"Peach".to_vec()),
                        ..DestinationAnnounceOptions::default()
                    })
                    .await?;
                println!("Announced {}", hex::encode(destination.handle.destination_hash()));
            }
        }
    }

    subscription.close().await?;
    destination.close().await?;
    runtime.stop().await;
    Ok(())
}
