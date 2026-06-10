//! Shared TCP socket tuning for [`crate::tcp`] and [`crate::backbone`].
//! `set_keepalive`: portable SO_KEEPALIVE. `set_keepalive_tuned`: adds Linux
//! TCP_KEEPIDLE/INTVL/CNT + TCP_USER_TIMEOUT.
//! `iface_addr_for`: kernel iface name → IpAddr for Backbone `device =` key.

use std::net::IpAddr;
use std::time::Duration;

use tokio::net::TcpStream;

/// Enable portable `SO_KEEPALIVE`; for tuned, use [`set_keepalive_tuned`].
#[cfg(unix)]
pub fn set_keepalive(stream: &TcpStream) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let raw_fd = stream.as_ref().as_raw_fd();
    // SAFETY: we borrow the fd without taking ownership (ManuallyDrop ensures
    // the socket2::Socket destructor does not close the fd).
    let sock = std::mem::ManuallyDrop::new(unsafe { socket2::Socket::from_raw_fd(raw_fd) });
    sock.set_keepalive(true)?;
    Ok(())
}

#[cfg(windows)]
pub fn set_keepalive(stream: &TcpStream) -> std::io::Result<()> {
    use std::os::windows::io::{AsRawSocket, FromRawSocket};
    let raw = stream.as_ref().as_raw_socket();
    let sock = std::mem::ManuallyDrop::new(unsafe { socket2::Socket::from_raw_socket(raw) });
    sock.set_keepalive(true)?;
    Ok(())
}

/// Enable portable `SO_KEEPALIVE` on a blocking std TCP stream.
#[cfg(unix)]
pub fn set_keepalive_std(stream: &std::net::TcpStream) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let raw_fd = stream.as_raw_fd();
    let sock = std::mem::ManuallyDrop::new(unsafe { socket2::Socket::from_raw_fd(raw_fd) });
    sock.set_keepalive(true)?;
    Ok(())
}

#[cfg(windows)]
pub fn set_keepalive_std(stream: &std::net::TcpStream) -> std::io::Result<()> {
    use std::os::windows::io::{AsRawSocket, FromRawSocket};
    let raw = stream.as_raw_socket();
    let sock = std::mem::ManuallyDrop::new(unsafe { socket2::Socket::from_raw_socket(raw) });
    sock.set_keepalive(true)?;
    Ok(())
}

/// Tuned keepalive: idle/interval/retries + Linux TCP_USER_TIMEOUT. Best-effort.
#[cfg(unix)]
pub fn set_keepalive_tuned(
    stream: &TcpStream,
    idle: Duration,
    intvl: Duration,
    retries: u32,
    user_timeout: Duration,
) {
    use std::os::fd::{AsRawFd, FromRawFd};
    let raw_fd = stream.as_ref().as_raw_fd();
    let sock = std::mem::ManuallyDrop::new(unsafe { socket2::Socket::from_raw_fd(raw_fd) });
    apply_tuned_keepalive(&sock, idle, intvl, retries, user_timeout);
}

#[cfg(windows)]
pub fn set_keepalive_tuned(
    stream: &TcpStream,
    idle: Duration,
    intvl: Duration,
    retries: u32,
    user_timeout: Duration,
) {
    use std::os::windows::io::{AsRawSocket, FromRawSocket};
    let raw = stream.as_ref().as_raw_socket();
    let sock = std::mem::ManuallyDrop::new(unsafe { socket2::Socket::from_raw_socket(raw) });
    apply_tuned_keepalive(&sock, idle, intvl, retries, user_timeout);
}

/// Tuned keepalive for blocking std TCP streams. Best-effort.
#[cfg(unix)]
pub fn set_keepalive_tuned_std(
    stream: &std::net::TcpStream,
    idle: Duration,
    intvl: Duration,
    retries: u32,
    user_timeout: Duration,
) {
    use std::os::fd::{AsRawFd, FromRawFd};
    let raw_fd = stream.as_raw_fd();
    let sock = std::mem::ManuallyDrop::new(unsafe { socket2::Socket::from_raw_fd(raw_fd) });
    apply_tuned_keepalive(&sock, idle, intvl, retries, user_timeout);
}

#[cfg(windows)]
pub fn set_keepalive_tuned_std(
    stream: &std::net::TcpStream,
    idle: Duration,
    intvl: Duration,
    retries: u32,
    user_timeout: Duration,
) {
    use std::os::windows::io::{AsRawSocket, FromRawSocket};
    let raw = stream.as_raw_socket();
    let sock = std::mem::ManuallyDrop::new(unsafe { socket2::Socket::from_raw_socket(raw) });
    apply_tuned_keepalive(&sock, idle, intvl, retries, user_timeout);
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

/// Raise TCP send/recv buffers; best-effort.
#[cfg(unix)]
pub fn set_socket_buffers(stream: &TcpStream, size: usize) {
    use std::os::fd::{AsRawFd, FromRawFd};
    let raw_fd = stream.as_ref().as_raw_fd();
    let sock = std::mem::ManuallyDrop::new(unsafe { socket2::Socket::from_raw_fd(raw_fd) });
    let _ = sock.set_recv_buffer_size(size);
    let _ = sock.set_send_buffer_size(size);
}

#[cfg(windows)]
pub fn set_socket_buffers(stream: &TcpStream, size: usize) {
    use std::os::windows::io::{AsRawSocket, FromRawSocket};
    let raw = stream.as_ref().as_raw_socket();
    let sock = std::mem::ManuallyDrop::new(unsafe { socket2::Socket::from_raw_socket(raw) });
    let _ = sock.set_recv_buffer_size(size);
    let _ = sock.set_send_buffer_size(size);
}

/// Raise TCP send/recv buffers on a blocking std TCP stream; best-effort.
#[cfg(unix)]
pub fn set_socket_buffers_std(stream: &std::net::TcpStream, size: usize) {
    use std::os::fd::{AsRawFd, FromRawFd};
    let raw_fd = stream.as_raw_fd();
    let sock = std::mem::ManuallyDrop::new(unsafe { socket2::Socket::from_raw_fd(raw_fd) });
    let _ = sock.set_recv_buffer_size(size);
    let _ = sock.set_send_buffer_size(size);
}

#[cfg(windows)]
pub fn set_socket_buffers_std(stream: &std::net::TcpStream, size: usize) {
    use std::os::windows::io::{AsRawSocket, FromRawSocket};
    let raw = stream.as_raw_socket();
    let sock = std::mem::ManuallyDrop::new(unsafe { socket2::Socket::from_raw_socket(raw) });
    let _ = sock.set_recv_buffer_size(size);
    let _ = sock.set_send_buffer_size(size);
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
    use tokio::net::TcpListener;

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

    #[test]
    fn std_keepalive_and_buffers_apply_without_panic() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || listener.accept().unwrap().0);
        let client = std::net::TcpStream::connect(addr).unwrap();
        let server = accept.join().unwrap();

        set_keepalive_std(&server).expect("server set_keepalive_std");
        set_keepalive_std(&client).expect("client set_keepalive_std");

        set_keepalive_tuned_std(
            &server,
            Duration::from_secs(5),
            Duration::from_secs(2),
            12,
            Duration::from_secs(24),
        );
        set_keepalive_tuned_std(
            &client,
            Duration::from_secs(5),
            Duration::from_secs(2),
            12,
            Duration::from_secs(24),
        );

        set_socket_buffers_std(&server, 131_072);
        set_socket_buffers_std(&client, 131_072);
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
