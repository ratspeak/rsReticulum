mod support;

use std::time::Duration;

use rns_runtime::prelude::*;
use support::*;

const ASPECT: &str = "example_utilities.requestexample";
const REQUEST_PATH: &str = "/echo";

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
    let destination = register_single(
        &runtime.handle,
        Identity::new(),
        ASPECT,
        DestinationRuntimeOptions::default(),
    )
    .await?;
    destination
        .handle
        .register_request_handler(
            REQUEST_PATH,
            AllowPolicy::AllowAll,
            Vec::new(),
            true,
            |request| {
                println!(
                    "{} requested {} bytes on {}",
                    hex::encode(request.link_id),
                    request.data.len(),
                    request.path,
                );
                RequestOutcome::Reply(request.data)
            },
        )
        .await?;
    print_destination("Request destination", destination.handle.destination_hash());
    destination
        .handle
        .announce(DestinationAnnounceOptions::default())
        .await?;

    runtime.shutdown.wait().await;
    destination.close().await?;
    runtime.stop().await;
    Ok(())
}

async fn client(args: ExampleArgs) -> ExampleResult {
    let destination_hash = parse_destination_hash(args.require(1, "destination hash")?)?;
    let message = args
        .positional
        .get(2)
        .map_or("Hello request", String::as_str);
    let runtime = ExampleRuntime::start(args.config_dir.as_deref()).await?;
    let session = connect(&runtime.handle, destination_hash, false, "request-example").await?;
    let response = session
        .handle
        .request(
            REQUEST_PATH,
            message.as_bytes(),
            Some(Duration::from_secs(30)),
        )
        .await?;
    println!(
        "Response in {:.3} ms: {}",
        response.response_time.as_secs_f64() * 1000.0,
        String::from_utf8_lossy(&response.data),
    );

    session.handle.close().await;
    runtime.stop().await;
    Ok(())
}
