//! Shared TCP socket tuning for [`crate::tcp`], [`crate::backbone`],
//! [`crate::i2p`], and [`crate::rnode`] (TCP transport).
//! `set_keepalive`: portable SO_KEEPALIVE. `set_keepalive_tuned`: adds Linux
//! TCP_KEEPIDLE/INTVL/CNT + TCP_USER_TIMEOUT. All helpers are generic over
//! the raw-fd/raw-socket borrow, so they accept tokio and std streams alike.
//! `iface_addr_for`: kernel iface name → IpAddr for Backbone `device =` key.

use std::net::IpAddr;
use std::time::Duration;

/// Borrow the raw fd/socket as a `socket2::Socket` without taking ownership
/// (`ManuallyDrop` keeps the destructor from closing it).
#[cfg(unix)]
fn with_socket2<S: std::os::fd::AsRawFd, R>(
    stream: &S,
    f: impl FnOnce(&socket2::Socket) -> R,
) -> R {
    use std::os::fd::FromRawFd;
    // SAFETY: we borrow the fd without taking ownership (ManuallyDrop ensures
    // the socket2::Socket destructor does not close the fd).
    let sock =
        std::mem::ManuallyDrop::new(unsafe { socket2::Socket::from_raw_fd(stream.as_raw_fd()) });
    f(&sock)
}

#[cfg(windows)]
fn with_socket2<S: std::os::windows::io::AsRawSocket, R>(
    stream: &S,
    f: impl FnOnce(&socket2::Socket) -> R,
) -> R {
    use std::os::windows::io::FromRawSocket;
    // SAFETY: same borrow-without-ownership contract as the unix variant.
    let sock = std::mem::ManuallyDrop::new(unsafe {
        socket2::Socket::from_raw_socket(stream.as_raw_socket())
    });
    f(&sock)
}

/// Platform bound for streams the tuning helpers accept: anything exposing
/// the raw socket handle (tokio `TcpStream`, std `TcpStream`, …).
#[cfg(unix)]
pub trait RawStream: std::os::fd::AsRawFd {}
#[cfg(unix)]
impl<T: std::os::fd::AsRawFd> RawStream for T {}

#[cfg(windows)]
pub trait RawStream: std::os::windows::io::AsRawSocket {}
#[cfg(windows)]
impl<T: std::os::windows::io::AsRawSocket> RawStream for T {}

/// Enable portable `SO_KEEPALIVE`; for tuned, use [`set_keepalive_tuned`].
pub fn set_keepalive<S: RawStream>(stream: &S) -> std::io::Result<()> {
    with_socket2(stream, |sock| sock.set_keepalive(true))
}

/// Tuned keepalive: idle/interval/retries + Linux TCP_USER_TIMEOUT. Best-effort.
pub fn set_keepalive_tuned<S: RawStream>(
    stream: &S,
    idle: Duration,
    intvl: Duration,
    retries: u32,
    user_timeout: Duration,
) {
    with_socket2(stream, |sock| {
        apply_tuned_keepalive(sock, idle, intvl, retries, user_timeout)
    });
}

/// Raise TCP send/recv buffers; best-effort.
pub fn set_socket_buffers<S: RawStream>(stream: &S, size: usize) {
    with_socket2(stream, |sock| {
        let _ = sock.set_recv_buffer_size(size);
        let _ = sock.set_send_buffer_size(size);
    });
}

fn apply_tuned_keepalive(
    sock: &socket2::Socket,
    idle: Duration,
    intvl: Duration,
    retries: u32,
    user_timeout: Duration,
) {
    let ka = socket2::TcpKeepalive::new().with_time(idle);
    #[cfg(any(unix, windows))]
    let ka = ka.with_interval(intvl);
    #[cfg(not(any(unix, windows)))]
    let _ = intvl;
    #[cfg(unix)]
    let ka = ka.with_retries(retries);
    #[cfg(not(unix))]
    let _ = retries;

    if let Err(e) = sock.set_tcp_keepalive(&ka) {
        tracing::warn!(error = %e, "set_tcp_keepalive failed");
    }

    // TCP_USER_TIMEOUT — Linux-family only.
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
    if let Err(e) = sock.set_tcp_user_timeout(Some(user_timeout)) {
        tracing::warn!(error = %e, "set_tcp_user_timeout failed");
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "fuchsia")))]
    let _ = user_timeout;
}

/// Resolve interface name to its IPv4 broadcast address; `None` if the
/// interface is missing or has no broadcast-capable IPv4. Python UDP
/// `device =` semantics (`get_broadcast_for_if`).
pub fn iface_broadcast_for(name: &str) -> Option<std::net::Ipv4Addr> {
    let ifaces = match if_addrs::get_if_addrs() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "if_addrs::get_if_addrs() failed");
            return None;
        }
    };
    ifaces.into_iter().filter(|i| i.name == name).find_map(|i| {
        if let if_addrs::IfAddr::V4(v4) = i.addr {
            v4.broadcast
        } else {
            None
        }
    })
}

/// Resolve interface name to `IpAddr`; `None` if missing. Caller falls back
/// to wildcard bind.
pub fn iface_addr_for(name: &str, prefer_ipv6: bool) -> Option<IpAddr> {
    let ifaces = match if_addrs::get_if_addrs() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "if_addrs::get_if_addrs() failed");
            return None;
        }
    };
    let matches: Vec<IpAddr> = ifaces
        .into_iter()
        .filter(|i| i.name == name)
        .map(|i| i.addr.ip())
        .collect();
    if matches.is_empty() {
        return None;
    }
    if prefer_ipv6 {
        matches
            .iter()
            .find(|a| a.is_ipv6())
            .copied()
            .or_else(|| matches.first().copied())
    } else {
        matches
            .iter()
            .find(|a| a.is_ipv4())
            .copied()
            .or_else(|| matches.first().copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn keepalive_and_buffers_apply_without_panic() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (server_accept, client_connect) =
            tokio::join!(listener.accept(), TcpStream::connect(addr));
        let (server, _) = server_accept.unwrap();
        let client = client_connect.unwrap();

        set_keepalive(&server).expect("server set_keepalive");
        set_keepalive(&client).expect("client set_keepalive");

        // Tuned keepalive — must not panic on any platform.
        set_keepalive_tuned(
            &server,
            Duration::from_secs(5),
            Duration::from_secs(2),
            12,
            Duration::from_secs(24),
        );
        set_keepalive_tuned(
            &client,
            Duration::from_secs(5),
            Duration::from_secs(2),
            12,
            Duration::from_secs(24),
        );

        set_socket_buffers(&server, 131_072);
        set_socket_buffers(&client, 131_072);
    }

    /// The same generic helpers must accept blocking std streams.
    #[test]
    fn std_keepalive_and_buffers_apply_without_panic() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || listener.accept().unwrap().0);
        let client = std::net::TcpStream::connect(addr).unwrap();
        let server = accept.join().unwrap();

        set_keepalive(&server).expect("server set_keepalive");
        set_keepalive(&client).expect("client set_keepalive");

        set_keepalive_tuned(
            &server,
            Duration::from_secs(5),
            Duration::from_secs(2),
            12,
            Duration::from_secs(24),
        );
        set_keepalive_tuned(
            &client,
            Duration::from_secs(5),
            Duration::from_secs(2),
            12,
            Duration::from_secs(24),
        );

        set_socket_buffers(&server, 131_072);
        set_socket_buffers(&client, 131_072);
    }

    #[test]
    fn iface_addr_for_loopback_resolves() {
        // Loopback name varies by OS; iterate candidates.
        let candidates = ["lo", "lo0", "Loopback Pseudo-Interface 1"];
        let mut found_v4 = false;
        for name in candidates {
            if let Some(IpAddr::V4(v4)) = iface_addr_for(name, false) {
                if v4.is_loopback() {
                    found_v4 = true;
                    break;
                }
            }
        }
        // Hermetic CI may not expose loopback by name; only assert when seen.
        if let Ok(ifaces) = if_addrs::get_if_addrs() {
            if ifaces.iter().any(|i| candidates.contains(&i.name.as_str())) {
                assert!(
                    found_v4,
                    "expected a loopback IPv4 on one of {candidates:?}"
                );
            }
        }
    }

    #[test]
    fn iface_addr_for_missing_returns_none() {
        assert!(iface_addr_for("definitely-not-a-real-interface-zzz", false).is_none());
    }
}
