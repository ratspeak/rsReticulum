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
