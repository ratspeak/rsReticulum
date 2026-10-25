//! A SAM session's private key, read from its key file or returned by the SAM
//! bridge, must not survive in freed heap memory.

#[path = "../../rns-crypto/tests/residue/mod.rs"]
mod residue;

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use residue::{assert_no_residue, freed_by, pseudo_random, serial};
use rns_interface::i2p::{I2PClientConfig, I2PServerConfig, spawn_i2p_client, spawn_i2p_server};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";

/// A SAM private key: a destination of 384 key bytes and an Ed25519 key
/// certificate, then 256 private and 32 signing-key bytes. Returns the key's
/// bytes and its I2P base64 text.
fn sam_private_key(seed: u64) -> (Vec<u8>, String) {
    let mut key = pseudo_random::<384>(seed).to_vec();
    key.extend_from_slice(&[5, 0, 4, 0, 7, 0, 0]);
    key.extend_from_slice(&pseudo_random::<288>(seed + 1));
    let mut text = String::new();
    for chunk in key.chunks(3) {
        let bits = chunk.iter().enumerate().fold(0u32, |bits, (n, byte)| {
            bits | u32::from(*byte) << (16 - 8 * n)
        });
        for n in 0..=chunk.len() {
            text.push(char::from(ALPHABET[(bits >> (18 - 6 * n)) as usize & 63]));
        }
        text.extend(std::iter::repeat_n('=', 3 - chunk.len()));
    }
    (key, text)
}

/// A SAM bridge on its own threads, so none of its frees are recorded. A
/// session keeps the key it asks for, a transient one gets `transient`, and a
/// STREAM CONNECT succeeds; every socket then stays open.
fn sam_bridge(transient: String) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for socket in listener.incoming() {
            let Ok(socket) = socket else { return };
            let transient = transient.clone();
            std::thread::spawn(move || serve(socket, &transient));
        }
    });
    port
}

fn serve(mut socket: TcpStream, transient: &str) {
    let mut reader = BufReader::new(socket.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let _ = socket.write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n");
    line.clear();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    if line.starts_with("SESSION CREATE") {
        let destination = match line
            .split_whitespace()
            .find_map(|token| token.strip_prefix("DESTINATION="))
        {
            Some("TRANSIENT") | None => transient,
            Some(key) => key,
        };
        let _ = socket
            .write_all(format!("SESSION STATUS RESULT=OK DESTINATION={destination}\n").as_bytes());
    } else if line.starts_with("STREAM CONNECT") {
        let _ = socket.write_all(b"STREAM STATUS RESULT=OK\n");
    }
    let mut rest = Vec::new();
    let _ = std::io::Read::read_to_end(&mut reader, &mut rest);
}

/// Run `body` on a current-thread runtime inside the check, then drop the
/// runtime there too, so every task's frees are recorded.
fn checked(body: impl std::future::Future<Output = ()>) -> residue::Freed {
    let ((), freed) = freed_by(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(body);
        drop(runtime);
    });
    freed
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(label: &str) -> TempDir {
    let path = std::env::temp_dir().join(format!("rns-i2p-residue-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    TempDir(path)
}

async fn run_server(sam_port: u16, key_path: PathBuf) {
    let (b32_tx, mut b32_rx) = tokio::sync::watch::channel(None);
    let mut config = I2PServerConfig::new("residue");
    config.sam_host = "127.0.0.1".into();
    config.sam_port = sam_port;
    config.key_path = Some(key_path);
    config.b32 = Some(b32_tx);
    let (transport_tx, _transport_rx) = tokio::sync::mpsc::channel(16);
    let (handle_tx, _handle_rx) = tokio::sync::mpsc::channel(16);
    let _handle = spawn_i2p_server(
        config,
        1,
        Arc::new(AtomicU64::new(2)),
        transport_tx,
        handle_tx,
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), b32_rx.wait_for(Option::is_some))
        .await
        .expect("session created")
        .unwrap();
    // Let the server reach its STREAM ACCEPT.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[test]
fn i2p_server_with_a_stored_key_frees_no_private_key() {
    let _serial = serial();
    let (key, text) = sam_private_key(10);
    let sam_port = sam_bridge(sam_private_key(11).1);
    let dir = temp_dir("stored");
    let key_path = dir.0.join("i2p.key");
    std::fs::write(&key_path, format!("{text}\n")).unwrap();

    let freed = checked(run_server(sam_port, key_path));

    assert_no_residue(
        &freed,
        &[("private key text", text.as_bytes()), ("private key", &key)],
    );
}

#[test]
fn i2p_server_storing_a_new_key_frees_no_private_key() {
    let _serial = serial();
    let (key, text) = sam_private_key(20);
    let sam_port = sam_bridge(text.clone());
    let dir = temp_dir("new");
    let key_path = dir.0.join("i2p.key");

    let freed = checked(run_server(sam_port, key_path.clone()));

    assert_eq!(std::fs::read_to_string(&key_path).unwrap(), text);
    assert_no_residue(
        &freed,
        &[("private key text", text.as_bytes()), ("private key", &key)],
    );
}

#[test]
fn i2p_client_session_frees_no_private_key() {
    let _serial = serial();
    let (key, text) = sam_private_key(30);
    let sam_port = sam_bridge(text.clone());
    let peer = sam_private_key(40).1;

    let freed = checked(async move {
        let mut config = I2PClientConfig::new("residue", &peer[..516]);
        config.sam_host = "127.0.0.1".into();
        config.sam_port = sam_port;
        let (transport_tx, mut transport_rx) = tokio::sync::mpsc::channel(16);
        let handle = spawn_i2p_client(config, 1, transport_tx).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while !handle.online.load(Ordering::SeqCst) {
                tokio::select! {
                    _ = transport_rx.recv() => {}
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
            }
        })
        .await
        .expect("client online");
    });

    assert_no_residue(
        &freed,
        &[("private key text", text.as_bytes()), ("private key", &key)],
    );
}

#[test]
fn i2p_server_debug_output_hides_its_key() {
    let (_, text) = sam_private_key(50);
    let mut config = I2PServerConfig::new("residue");
    config.keyfile = Some(text.clone());

    let shown = format!("{config:?}");

    assert!(!shown.contains(&text[..32]), "{shown}");
    assert!(shown.contains("residue"), "{shown}");
}
