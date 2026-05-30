//! Bridges a PIV token to an `rns_identity::Identity` via the `LocalKeyBackend`
//! seam. The PIV session runs on a dedicated thread — pcsc handles want serial
//! APDU access and are not `Sync` — so the backend handle holds only channel
//! senders and is therefore `Send + Sync`, usable directly from the async runtime.

use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use rns_identity::identity::{Identity, LocalKeyBackend};

use crate::apdu::{SLOT_AUTHENTICATION, SLOT_KEY_MANAGEMENT};
use crate::error::RatkeyError;
use crate::hwid::HwidConfig;
use crate::session::PivSession;
use crate::transport::PcscTransport;

enum Cmd {
    Sign {
        message: Vec<u8>,
        reply: Sender<Option<[u8; 64]>>,
    },
    Ecdh {
        peer_pub: [u8; 32],
        reply: Sender<Option<[u8; 32]>>,
    },
    /// Re-select the PIV applet to drop the on-card PIN cache. Acknowledged so
    /// callers (lock-on-quit / timeout) can block until the card is re-locked.
    Lock { reply: Sender<()> },
}

/// `LocalKeyBackend` over a PIV token. Each call round-trips a request to the
/// card-service thread and blocks for the device's reply (PIV ops are ~10-50ms).
pub struct HardwareBackend {
    cmd_tx: Mutex<Sender<Cmd>>,
}

impl LocalKeyBackend for HardwareBackend {
    fn sign_ed25519(&self, message: &[u8]) -> Option<[u8; 64]> {
        let (reply, rx) = mpsc::channel();
        self.cmd_tx
            .lock()
            .ok()?
            .send(Cmd::Sign {
                message: message.to_vec(),
                reply,
            })
            .ok()?;
        rx.recv().ok().flatten()
    }

    fn ecdh(&self, peer_pub: &[u8; 32]) -> Option<[u8; 32]> {
        let (reply, rx) = mpsc::channel();
        self.cmd_tx
            .lock()
            .ok()?
            .send(Cmd::Ecdh {
                peer_pub: *peer_pub,
                reply,
            })
            .ok()?;
        rx.recv().ok().flatten()
    }

    fn lock(&self) {
        let (reply, rx) = mpsc::channel();
        if let Ok(tx) = self.cmd_tx.lock()
            && tx.send(Cmd::Lock { reply }).is_ok()
        {
            let _ = rx.recv();
        }
    }
}

/// Connect to the token described by `hwid`, verify the on-device keys match it
/// (fail-closed), unlock with `pin`, and return an `Identity` whose private
/// operations run on the device. The PIV session lives on a worker thread that
/// exits when the returned identity (and its backend) is dropped.
pub fn load_hardware_identity(hwid: &HwidConfig, pin: &str) -> Result<Identity, RatkeyError> {
    let ed_pub = hwid.ed25519_pub_bytes()?;
    let x_pub = hwid.x25519_pub_bytes()?;
    let pin = pin.to_string();

    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), RatkeyError>>();

    thread::Builder::new()
        .name("ratkey-piv".to_string())
        .spawn(move || {
            let mut session = match PivSession::<PcscTransport>::connect() {
                Ok(s) => s,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            // Fail closed: the device's slot keys must match the .hwid.
            match (
                session.read_public_key(SLOT_AUTHENTICATION),
                session.read_public_key(SLOT_KEY_MANAGEMENT),
            ) {
                (Ok(de), Ok(dx)) if de == ed_pub && dx == x_pub => {}
                (Ok(_), Ok(_)) => {
                    let _ = ready_tx.send(Err(RatkeyError::KeyMismatch));
                    return;
                }
                (Err(e), _) | (_, Err(e)) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            }
            if let Err(e) = session.verify_pin(&pin) {
                let _ = ready_tx.send(Err(e));
                return;
            }
            let _ = ready_tx.send(Ok(()));

            // Serve sign/ECDH until the backend is dropped (sender closed).
            while let Ok(cmd) = cmd_rx.recv() {
                match cmd {
                    Cmd::Sign { message, reply } => {
                        let _ =
                            reply.send(session.sign_ed25519(SLOT_AUTHENTICATION, &message).ok());
                    }
                    Cmd::Ecdh { peer_pub, reply } => {
                        let _ =
                            reply.send(session.ecdh_x25519(SLOT_KEY_MANAGEMENT, &peer_pub).ok());
                    }
                    Cmd::Lock { reply } => {
                        let locked = session.lock().is_ok();
                        tracing::debug!(locked, "PIV applet re-selected (PIN cache dropped)");
                        let _ = reply.send(());
                    }
                }
            }
        })
        .map_err(|e| RatkeyError::Io(std::io::Error::other(e.to_string())))?;

    // Wait for the worker to connect, match, and unlock before handing back.
    ready_rx.recv().map_err(|_| RatkeyError::NoDevice)??;

    let mut pub64 = [0u8; 64];
    pub64[..32].copy_from_slice(&x_pub);
    pub64[32..].copy_from_slice(&ed_pub);
    Identity::from_backend(
        &pub64,
        Arc::new(HardwareBackend {
            cmd_tx: Mutex::new(cmd_tx),
        }),
    )
    .map_err(|e| RatkeyError::InvalidHwid(format!("cannot build identity: {e}")))
}
