mod support;

use rns_runtime::prelude::*;
use support::*;

const ASPECT: &str = "example_utilities.resourceexample";

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
            resource_strategy: ResourceStrategy::AcceptAll,
            ..DestinationRuntimeOptions::default()
        },
    )
    .await?;
    print_destination(
        "Resource destination",
        destination.handle.destination_hash(),
    );
    destination
        .handle
        .announce(DestinationAnnounceOptions::default())
        .await?;

    loop {
        tokio::select! {
            _ = runtime.shutdown.wait() => break,
            completed = destination.events.resource_completions.recv() => {
                let Some(completed) = completed else { break };
                println!(
                    "Received {} bytes on {} as {}",
                    completed.data.len(),
                    hex::encode(completed.link_id),
                    hex::encode(completed.resource_hash),
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
    let message = args
        .positional
        .get(2)
        .map_or("Hello Resource", String::as_str);
    let runtime = ExampleRuntime::start(args.config_dir.as_deref()).await?;
    let session = connect(&runtime.handle, destination_hash, false, "resource-example").await?;
    let transfer = session
        .handle
        .send_resource_bytes(
            message.as_bytes().to_vec(),
            ResourceOptions {
                auto_compress: true,
                metadata: None,
            },
        )
        .await?;
    let mut progress = transfer.progress();
    let concluded = transfer.concluded();
    tokio::pin!(concluded);

    let receipt = loop {
        tokio::select! {
            result = &mut concluded => break result?,
            changed = progress.changed() => {
                changed?;
                println!("Progress: {:.1}%", *progress.borrow() * 100.0);
            }
        }
    };
    println!(
        "Resource {} completed ({} bytes)",
        hex::encode(receipt.resource_id),
        receipt.data_size,
    );

    session.handle.close().await;
    runtime.stop().await;
    Ok(())
}
