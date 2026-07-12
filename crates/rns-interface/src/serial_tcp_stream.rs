//! Shared serial/TCP transport for the KISS-family interfaces (KISS, RNode).
//!
//! A [`SerialTcpStream`] is either a local serial port or a TCP socket
//! behind one blocking `Read + Write` interface, so callers drive both the
//! same way: through `spawn_blocking` shuttles (see [`crate::serial_io`])
//! for the data path, and [`read_stream`] for a single bounded read that
//! treats an idle timeout uniformly across both transports.
//!
//! Port selection is driven by the config string:
//!   - `/dev/ttyUSB0`, `COM3`, etc.  -> serial (feature `serial` required)
//!   - `tcp://192.168.1.1`           -> TCP, [`DEFAULT_TCP_PORT`]
//!   - `tcp://192.168.1.1:9000`      -> TCP, explicit port

use std::time::Duration;

/// Read timeout applied to both serial ports and TCP sockets so the caller's
/// read loop can periodically re-check its exit/online flag.
pub const READ_TIMEOUT_MS: u64 = 100;

const TCP_CONNECT_TIMEOUT_SECS: u64 = 5;
const TCP_KEEPIDLE_SECS: u64 = 5;
const TCP_KEEPINTVL_SECS: u64 = 2;
const TCP_KEEPCNT: u32 = 12;
const TCP_USER_TIMEOUT_SECS: u64 = 24;
const TCP_BUFFER_BYTES: usize = 131_072;

/// Delay between reconnect attempts after a transport drop.
pub const RECONNECT_WAIT_SECS: u64 = 5;

/// Backoff before a driver retries opening its transport after a failure.
/// Shortened under `#[cfg(test)]` so reconnect tests don't sit idle.
pub fn reconnect_delay() -> Duration {
    #[cfg(test)]
    {
        Duration::from_millis(100)
    }
    #[cfg(not(test))]
    {
        Duration::from_secs(RECONNECT_WAIT_SECS)
    }
}

/// Parsed representation of a `port` config field.
#[derive(Debug, Clone)]
pub enum PortConfig {
    /// A local serial device path, e.g. `/dev/ttyUSB0` or `COM3`.
    #[cfg(feature = "serial")]
    Serial { path: String, baud: u32 },
    /// A TCP endpoint, e.g. `tcp://192.168.1.1` or `tcp://192.168.1.1:9000`.
    Tcp { addr: String },
}

impl PortConfig {
    pub fn parse(port: &str, baud: u32) -> Result<Self, String> {
        #[cfg(not(feature = "serial"))]
        let _ = baud;

        if let Some(rest) = strip_tcp_scheme(port) {
            let addr = parse_tcp_endpoint(rest)?;
            Ok(Self::Tcp { addr })
        } else {
            #[cfg(feature = "serial")]
            {
                Ok(Self::Serial {
                    path: port.to_string(),
                    baud,
                })
            }
            #[cfg(not(feature = "serial"))]
            Err(
                "serial ports require the 'serial' feature; use tcp://host[:port] for TCP"
                    .to_string(),
            )
        }
    }
}

fn strip_tcp_scheme(port: &str) -> Option<&str> {
    const TCP_SCHEME: &str = "tcp://";
    port.get(..TCP_SCHEME.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(TCP_SCHEME))
        .and_then(|_| port.get(TCP_SCHEME.len()..))
}

fn parse_tcp_endpoint(endpoint: &str) -> Result<String, String> {
    if endpoint.is_empty() {
        return Err("missing TCP host".to_string());
    }

    if let Some(rest) = endpoint.strip_prefix('[') {
        let Some(closing) = rest.find(']') else {
            return Err("missing closing ']' in IPv6 TCP host".to_string());
        };
        let host = &rest[..closing];
        if host.is_empty() {
            return Err("missing TCP host".to_string());
        }

        let tail = &rest[closing + 1..];
        let port = if tail.is_empty() {
            DEFAULT_TCP_PORT
        } else if let Some(port) = tail.strip_prefix(':') {
            parse_tcp_port(port)?
        } else {
            return Err("unexpected text after bracketed TCP host".to_string());
        };

        return Ok(format!("[{host}]:{port}"));
    }

    let colon_count = endpoint.matches(':').count();
    match colon_count {
        0 => Ok(format!("{endpoint}:{DEFAULT_TCP_PORT}")),
        1 => {
            let (host, port) = endpoint
                .rsplit_once(':')
                .expect("colon_count guarantees a separator");
            if host.is_empty() {
                return Err("missing TCP host".to_string());
            }
            Ok(format!("{host}:{}", parse_tcp_port(port)?))
        }
        _ => Ok(format!("[{endpoint}]:{DEFAULT_TCP_PORT}")),
    }
}

fn parse_tcp_port(port: &str) -> Result<u16, String> {
    if port.is_empty() {
        return Err("missing TCP port".to_string());
    }
    port.parse::<u16>()
        .map_err(|_| format!("invalid TCP port: {port}"))
}

/// Default TCP port for KISS/RNode-over-IP.
pub const DEFAULT_TCP_PORT: u16 = 7633;

/// A unified sync I/O stream for either a serial port or a TCP socket.
///
/// Both variants support `Read + Write + Send + 'static` so blocking
/// read/write shuttles (`spawn_blocking`) require no per-transport branching
/// at the call site.
pub enum SerialTcpStream {
    #[cfg(feature = "serial")]
    Serial(Box<dyn serialport::SerialPort>),
    Tcp(std::net::TcpStream),
}

impl SerialTcpStream {
    /// Open a serial port.
    #[cfg(feature = "serial")]
    pub fn open_serial(path: &str, baud: u32) -> std::io::Result<Self> {
        let port = serialport::new(path, baud)
            .timeout(Duration::from_millis(READ_TIMEOUT_MS))
            .open()
            .map_err(std::io::Error::other)?;
        Ok(Self::Serial(port))
    }

    /// Connect to a TCP socket (blocking) with the default connect timeout.
    pub fn connect_tcp(addr: &str) -> std::io::Result<Self> {
        Self::connect_tcp_with_timeout(addr, Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS))
    }

    pub fn connect_tcp_with_timeout(addr: &str, timeout: Duration) -> std::io::Result<Self> {
        use std::net::ToSocketAddrs;

        let mut last_error = None;
        for socket_addr in addr.to_socket_addrs()? {
            match std::net::TcpStream::connect_timeout(&socket_addr, timeout) {
                Ok(stream) => return Self::from_tcp_stream(stream),
                Err(e) => last_error = Some(e),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("no socket addresses resolved for {addr}"),
            )
        }))
    }

    fn from_tcp_stream(stream: std::net::TcpStream) -> std::io::Result<Self> {
        // Mirror the serial timeout so the read loop doesn't block forever.
        stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))?;
        stream.set_nodelay(true)?;
        crate::socket_tuning::set_keepalive_tuned(
            &stream,
            Duration::from_secs(TCP_KEEPIDLE_SECS),
            Duration::from_secs(TCP_KEEPINTVL_SECS),
            TCP_KEEPCNT,
            Duration::from_secs(TCP_USER_TIMEOUT_SECS),
        );
        crate::socket_tuning::set_socket_buffers(&stream, TCP_BUFFER_BYTES);
        Ok(Self::Tcp(stream))
    }

    /// Shallow-clone the stream for the write half.
    ///
    /// - Serial: uses `SerialPort::try_clone`.
    /// - TCP: uses `TcpStream::try_clone` (both halves share the same fd).
    pub fn try_clone(&self) -> std::io::Result<Self> {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => Ok(Self::Serial(p.try_clone().map_err(std::io::Error::other)?)),
            Self::Tcp(s) => Ok(Self::Tcp(s.try_clone()?)),
        }
    }

    /// Human-readable description for log messages.
    pub fn description(&self) -> String {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => p.name().unwrap_or_else(|| "<unknown serial>".to_string()),
            Self::Tcp(s) => s
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "<unknown tcp>".to_string()),
        }
    }

    pub fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }
}

impl std::io::Read for SerialTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => p.read(buf),
            Self::Tcp(s) => s.read(buf),
        }
    }
}

impl std::io::Write for SerialTcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => p.write(buf),
            Self::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => p.flush(),
            Self::Tcp(s) => s.flush(),
        }
    }
}

/// One bounded synchronous read, meant to be run inside `spawn_blocking`.
///
/// Serial idle timeouts and TCP `WouldBlock`/`TimedOut` both fold into
/// "no data yet" (`n == 0`, stream returned for reuse). A TCP `Ok(0)` means
/// the peer closed the connection and surfaces as a real error — unlike
/// serial, where `Ok(0)` is a normal empty read.
pub fn read_stream(
    mut stream: SerialTcpStream,
    mut buf: [u8; 1024],
) -> Result<(SerialTcpStream, [u8; 1024], usize), (SerialTcpStream, std::io::Error)> {
    use std::io::Read;

    match stream.read(&mut buf) {
        Ok(0) if stream.is_tcp() => Err((
            stream,
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "TCP socket closed"),
        )),
        Ok(n) => Ok((stream, buf, n)),
        Err(e)
            if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock =>
        {
            Ok((stream, buf, 0))
        }
        Err(e) => Err((stream, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "serial")]
    #[test]
    fn test_port_config_serial() {
        let cfg = PortConfig::parse("/dev/ttyUSB0", 115200).unwrap();
        assert!(matches!(cfg, PortConfig::Serial { path, .. } if path == "/dev/ttyUSB0"));
    }

    #[test]
    fn test_port_config_tcp_default_port() {
        let cfg = PortConfig::parse("tcp://192.168.1.1", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "192.168.1.1:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[test]
    fn test_port_config_tcp_explicit_port() {
        let cfg = PortConfig::parse("tcp://192.168.1.1:9000", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "192.168.1.1:9000"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[test]
    fn test_port_config_tcp_hostname() {
        let cfg = PortConfig::parse("tcp://rnode.local", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "rnode.local:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[test]
    fn test_port_config_tcp_case_insensitive_scheme() {
        let cfg = PortConfig::parse("TCP://rnode.local", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "rnode.local:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[test]
    fn test_port_config_tcp_empty_host_rejected() {
        let err = PortConfig::parse("tcp://", 115200).unwrap_err();
        assert!(err.contains("missing TCP host"));
    }

    #[test]
    fn test_port_config_tcp_invalid_port_rejected() {
        let err = PortConfig::parse("tcp://rnode.local:notaport", 115200).unwrap_err();
        assert!(err.contains("invalid TCP port"));
    }

    #[test]
    fn test_port_config_tcp_missing_port_rejected() {
        let err = PortConfig::parse("tcp://rnode.local:", 115200).unwrap_err();
        assert!(err.contains("missing TCP port"));
    }

    #[test]
    fn test_port_config_tcp_bracketed_ipv6_default_port() {
        let cfg = PortConfig::parse("tcp://[2001:db8::1]", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "[2001:db8::1]:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[test]
    fn test_port_config_tcp_bracketed_ipv6_explicit_port() {
        let cfg = PortConfig::parse("tcp://[2001:db8::1]:9000", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "[2001:db8::1]:9000"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[test]
    fn test_port_config_tcp_unbracketed_ipv6_default_port() {
        let cfg = PortConfig::parse("tcp://2001:db8::1", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "[2001:db8::1]:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[test]
    fn test_port_config_tcp_malformed_bracketed_ipv6_rejected() {
        let err = PortConfig::parse("tcp://[2001:db8::1", 115200).unwrap_err();
        assert!(err.contains("missing closing"));
    }

    #[test]
    fn test_tcp_eof_is_read_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
        });

        let stream = SerialTcpStream::connect_tcp(&addr.to_string()).unwrap();
        let _clone = stream.try_clone().unwrap();
        accept.join().unwrap();

        match read_stream(stream, [0u8; 1024]) {
            Ok(_) => panic!("closed TCP socket should be EOF"),
            Err((_stream, err)) => assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof),
        }
    }

    #[test]
    fn test_tcp_connect_accepts_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
        });

        let stream = SerialTcpStream::connect_tcp_with_timeout(
            &addr.to_string(),
            Duration::from_millis(500),
        )
        .unwrap();
        assert!(stream.is_tcp());

        drop(stream);
        accept.join().unwrap();
    }
}
