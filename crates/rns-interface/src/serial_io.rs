//! Blocking-I/O shuttles shared by the serial-family interfaces (Serial,
//! KISS, AX.25 KISS, RNodeMulti). No mature async serial driver exists, so
//! each read/write moves the port through `spawn_blocking` and back.

/// One bounded blocking read. Serial idle timeouts surface as `n == 0` so
/// the caller's loop can re-check its exit flag. A panicked blocking task
/// folds into an `io::Error`.
#[cfg(feature = "serial")]
pub(crate) async fn poll_read<P>(
    mut port: P,
    mut buf: [u8; 1024],
) -> Result<(P, [u8; 1024], usize), std::io::Error>
where
    P: std::io::Read + Send + 'static,
{
    let result = tokio::task::spawn_blocking(move || match port.read(&mut buf) {
        Ok(n) => Ok((port, buf, n)),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok((port, buf, 0)),
        Err(e) => Err(e),
    })
    .await;
    match result {
        Ok(read_result) => read_result,
        Err(join_err) => Err(std::io::Error::other(join_err)),
    }
}

/// One blocking `write_all` + `flush`, returning the port for the next call.
pub(crate) async fn blocking_write_all<P>(mut port: P, data: Vec<u8>) -> Result<P, std::io::Error>
where
    P: std::io::Write + Send + 'static,
{
    let result = tokio::task::spawn_blocking(move || {
        port.write_all(&data)?;
        port.flush()?;
        Ok::<_, std::io::Error>(port)
    })
    .await;
    match result {
        Ok(write_result) => write_result,
        Err(join_err) => Err(std::io::Error::other(join_err)),
    }
}

#[cfg(feature = "serial")]
pub use supervisor::*;

/// Python's serial-family lifecycle (`SerialInterface`, `KISSInterface`,
/// `AX25KISSInterface`): open, settle, go online, run until an error, then
/// retry every `RECONNECT_WAIT` seconds while dropping outbound packets.
#[cfg(feature = "serial")]
mod supervisor {
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use tokio::sync::{mpsc, watch};

    use crate::background_announce::BackgroundAnnounceReceiver;

    pub(crate) type Port = Box<dyn serialport::SerialPort>;
    /// Opens the configured port; called again for every reconnect attempt.
    pub(crate) type PortOpener = Arc<dyn Fn() -> std::io::Result<Port> + Send + Sync>;

    /// Why one open-port generation ended.
    pub(crate) enum GenerationEnd {
        /// The read loop failed: Python's unrecoverable-error path.
        ReadFailed(std::io::Error),
        /// A write failed; the port is reopened like after a read error.
        WriteFailed(std::io::Error),
        /// The interface or the transport went away.
        Closed,
    }

    pub(crate) trait SerialGeneration: Send {
        fn outbound(&mut self) -> &mut mpsc::Receiver<Bytes>;
        fn background(&self) -> &BackgroundAnnounceReceiver;
        fn run(&mut self, port: Port) -> impl Future<Output = GenerationEnd> + Send;
    }

    /// Count of runtime port failures, which Python answers with `RNS.panic()`
    /// when `panic_on_interface_error` is set.
    #[derive(Clone)]
    pub struct SerialFailures(watch::Receiver<u64>);

    impl SerialFailures {
        pub(crate) fn channel() -> (watch::Sender<u64>, Self) {
            let (tx, rx) = watch::channel(0);
            (tx, Self(rx))
        }

        pub fn total(&self) -> u64 {
            *self.0.borrow()
        }

        /// Wait for the next failure. `None` means the driver has ended.
        pub async fn changed(&mut self) -> Option<u64> {
            self.0.changed().await.ok()?;
            Some(self.total())
        }
    }

    pub(crate) struct Supervisor {
        pub identity: String,
        pub opener: PortOpener,
        pub settle: Duration,
        pub online: Arc<AtomicBool>,
        pub failures: watch::Sender<u64>,
    }

    /// Drop outbound packets for `duration`, as Python's `process_outgoing`
    /// does while offline. False once the outbound channel has closed.
    async fn drop_outbound_for(rx: &mut mpsc::Receiver<Bytes>, duration: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            tokio::select! {
                packet = rx.recv() => if packet.is_none() { return false },
                _ = tokio::time::sleep_until(deadline) => return true,
            }
        }
    }

    async fn open_with(opener: &PortOpener) -> std::io::Result<Port> {
        let opener = opener.clone();
        tokio::task::spawn_blocking(move || opener())
            .await
            .unwrap_or_else(|error| Err(std::io::Error::other(error)))
    }

    impl Supervisor {
        pub(crate) async fn run<G: SerialGeneration>(self, mut generation: G, first: Option<Port>) {
            let reconnect_wait = Duration::from_secs(crate::rnode::RECONNECT_WAIT);
            let mut next = first;
            loop {
                let port = match next.take() {
                    Some(port) => Some(port),
                    None => match open_with(&self.opener).await {
                        Ok(port) => Some(port),
                        Err(error) => {
                            tracing::error!(
                                interface = %self.identity,
                                %error,
                                "Could not open serial port, Reticulum will attempt to bring up this interface periodically"
                            );
                            None
                        }
                    },
                };
                if let Some(port) = port {
                    if !drop_outbound_for(generation.outbound(), self.settle).await {
                        return;
                    }
                    self.online.store(true, Ordering::SeqCst);
                    rns_transport::notice!(interface = %self.identity, "serial port is now open");
                    let end = generation.run(port).await;
                    self.online.store(false, Ordering::SeqCst);
                    generation.background().retire_generation();
                    match end {
                        GenerationEnd::Closed => return,
                        GenerationEnd::ReadFailed(error) => {
                            tracing::error!(
                                interface = %self.identity,
                                %error,
                                "The interface experienced an unrecoverable error and is now offline. Reticulum will attempt to reconnect the interface periodically."
                            );
                            self.failures.send_modify(|total| *total += 1);
                        }
                        GenerationEnd::WriteFailed(error) => {
                            tracing::error!(
                                interface = %self.identity,
                                %error,
                                "serial write failed, the interface is offline and will be reconnected periodically"
                            );
                        }
                    }
                }
                if !drop_outbound_for(generation.outbound(), reconnect_wait).await {
                    return;
                }
            }
        }
    }
}
