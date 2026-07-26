mod support;

use std::time::Instant;

use rns_runtime::prelude::*;
use support::*;

const ASPECT: &str = "example_utilities.speedtest";
const DEFAULT_BYTES: usize = 2 * 1024 * 1024;

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
    print_destination(
        "Speed-test destination",
        destination.handle.destination_hash(),
    );
    destination
        .handle
        .announce(DestinationAnnounceOptions::default())
        .await?;

    let mut total = 0usize;
    let started = Instant::now();
    loop {
        tokio::select! {
            _ = runtime.shutdown.wait() => break,
            packet = destination.events.link_packets.recv() => {
                let Some((data, _)) = packet else { break };
                total = total.saturating_add(data.len());
                if total >= DEFAULT_BYTES {
                    let elapsed = started.elapsed().as_secs_f64();
                    println!(
                        "Received {total} bytes at {:.2} Mbit/s",
                        (total as f64 * 8.0) / elapsed / 1_000_000.0,
                    );
                    total = 0;
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
    let total_bytes = args
        .positional
        .get(2)
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(DEFAULT_BYTES);
    let runtime = ExampleRuntime::start(args.config_dir.as_deref()).await?;
    let session = connect(
        &runtime.handle,
        destination_hash,
        false,
        "speedtest-example",
    )
    .await?;
    let chunk = vec![0xAA; session.handle.mdu()];
    let started = Instant::now();
    let mut sent = 0usize;

    while sent < total_bytes {
        let count = (total_bytes - sent).min(chunk.len());
        session.handle.send_packet(chunk[..count].to_vec()).await?;
        sent += count;
    }
    let elapsed = started.elapsed().as_secs_f64();
    println!(
        "Queued {sent} bytes in {:.3}s ({:.2} Mbit/s)",
        elapsed,
        (sent as f64 * 8.0) / elapsed / 1_000_000.0,
    );

    session.handle.close().await;
    runtime.stop().await;
    Ok(())
}
