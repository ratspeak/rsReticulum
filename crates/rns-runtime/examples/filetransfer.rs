mod support;

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use rns_runtime::prelude::*;
use support::*;

const ASPECT: &str = "example_utilities.filetransfer.server";

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
    let output_path = args.require(1, "new output file")?.to_string();
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
        "File-transfer destination",
        destination.handle.destination_hash(),
    );
    destination
        .handle
        .announce(DestinationAnnounceOptions::default())
        .await?;
    println!("The first completed transfer will be written to {output_path}");

    // A Resource of 1 MiB or more arrives as a file of any size, assembled
    // where Reticulum keeps its Resources; a smaller one arrives as bytes.
    let resource_dir =
        rns_runtime::platform::StoragePaths::from_config_dir(&runtime.handle.config_dir)
            .resource_dir;
    let mut files = destination
        .handle
        .receive_resource_files(resource_dir, 1 << 20, 4)
        .await?;

    tokio::select! {
        _ = runtime.shutdown.wait() => {}
        Some(completed) = destination.events.resource_completions.recv() => {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output_path)?;
            output.write_all(&completed.data)?;
            output.sync_all()?;
            println!(
                "Wrote {} bytes to {} without replacing an existing file",
                completed.data.len(),
                output_path,
            );
        }
        Some(completed) = files.recv() => {
            // The received file is ours: copy it into place, then remove it.
            let copied = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output_path)
                .and_then(|mut output| {
                    std::io::copy(&mut File::open(&completed.path)?, &mut output)?;
                    output.sync_all()
                });
            std::fs::remove_file(&completed.path)?;
            copied?;
            println!(
                "Wrote {} bytes to {} without replacing an existing file",
                completed.size, output_path,
            );
        }
    }

    destination.close().await?;
    runtime.stop().await;
    Ok(())
}

async fn client(args: ExampleArgs) -> ExampleResult {
    let destination_hash = parse_destination_hash(args.require(1, "destination hash")?)?;
    let input_path = Path::new(args.require(2, "input file")?);
    let input = File::open(input_path)?;
    let file_name = input_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("resource")
        .as_bytes()
        .to_vec();

    let runtime = ExampleRuntime::start(args.config_dir.as_deref()).await?;
    let session = connect(
        &runtime.handle,
        destination_hash,
        false,
        "filetransfer-example",
    )
    .await?;
    let transfer = session
        .handle
        .send_resource(
            input,
            ResourceOptions {
                auto_compress: false,
                metadata: Some(file_name),
            },
        )
        .await?;
    let mut progress = transfer.progress();
    let concluded = transfer.concluded();
    tokio::pin!(concluded);

    loop {
        tokio::select! {
            result = &mut concluded => {
                let receipt = result?;
                println!(
                    "Transferred {} bytes as {}",
                    receipt.data_size,
                    hex::encode(receipt.resource_id),
                );
                break;
            }
            changed = progress.changed() => {
                changed?;
                println!("Progress: {:.1}%", *progress.borrow() * 100.0);
            }
        }
    }

    session.handle.close().await;
    runtime.stop().await;
    Ok(())
}
