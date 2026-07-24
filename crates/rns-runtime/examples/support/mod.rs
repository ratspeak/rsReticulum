#![allow(dead_code)]

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rns_runtime::lifecycle::install_signal_handlers;
use rns_runtime::prelude::*;

pub type ExampleResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

pub struct ExampleArgs {
    pub config_dir: Option<String>,
    pub positional: Vec<String>,
}

impl ExampleArgs {
    pub fn parse() -> ExampleResult<Self> {
        let mut config_dir = None;
        let mut positional = Vec::new();
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--config" {
                config_dir = Some(args.next().ok_or("--config requires a directory")?);
            } else {
                positional.push(arg);
            }
        }
        Ok(Self {
            config_dir,
            positional,
        })
    }

    pub fn require(&self, index: usize, label: &str) -> ExampleResult<&str> {
        self.positional
            .get(index)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {label}").into())
    }
}

pub struct ExampleRuntime {
    pub handle: ReticulumHandle,
    pub shutdown: ShutdownSignal,
}

impl ExampleRuntime {
    pub async fn start(config_dir: Option<&str>) -> ExampleResult<Self> {
        let shutdown = ShutdownSignal::new();
        let _signals = install_signal_handlers(shutdown.clone());
        let handle = init(
            config_dir,
            None,
            shutdown.clone(),
            Arc::new(AtomicBool::new(true)),
        )
        .await?;
        Ok(Self { handle, shutdown })
    }

    pub async fn stop(&self) {
        self.handle.shutdown_and_wait().await;
    }
}

pub fn parse_destination_hash(value: &str) -> ExampleResult<[u8; 16]> {
    let bytes = hex::decode(value)?;
    bytes
        .try_into()
        .map_err(|_| "destination hash must contain exactly 32 hexadecimal characters".into())
}

pub async fn recall_outbound_destination(
    runtime: &ReticulumHandle,
    destination_hash: [u8; 16],
    app_name: &str,
) -> ExampleResult<Destination> {
    let recalled = match runtime.recall(destination_hash).await? {
        Some(recalled) => recalled,
        None => {
            runtime
                .await_path(destination_hash, Duration::from_secs(15))
                .await?;
            runtime
                .recall(destination_hash)
                .await?
                .ok_or("destination identity was not learned from its announce")?
        }
    };
    let destination = Destination::new(
        Some(&recalled.identity),
        Direction::Out,
        DestType::Single,
        app_name,
    )?;
    if destination.hash != destination_hash {
        return Err(format!(
            "destination {} does not match application aspect {app_name}",
            hex::encode(destination_hash)
        )
        .into());
    }
    Ok(destination)
}

pub async fn connect(
    runtime: &ReticulumHandle,
    destination_hash: [u8; 16],
    identify: bool,
    label: &str,
) -> ExampleResult<LinkSession> {
    let options = LinkConnectOptions {
        identify,
        client_label: label.to_string(),
        ..LinkConnectOptions::default()
    };
    Ok(runtime
        .connect_link(destination_hash, Identity::new(), options)
        .await?)
}

pub async fn register_single(
    runtime: &ReticulumHandle,
    identity: Identity,
    app_name: &str,
    options: DestinationRuntimeOptions,
) -> ExampleResult<RegisteredDestination> {
    Ok(runtime
        .register_destination(identity, app_name.to_string(), options)
        .await?)
}

pub fn print_destination(label: &str, hash: [u8; 16]) {
    println!("{label}: {}", hex::encode(hash));
}
