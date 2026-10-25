//! Plaintext and key material must not survive in freed heap memory.
//!
//! A recording allocator copies every block the test thread frees while a
//! check runs; each check then searches those copies for its secrets.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, UnsafeCell};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use rns_crypto::{aes_cbc, hkdf, hmac, token};
use zeroize::Zeroizing;

const RECORD_CAPACITY: usize = 4 << 20;

struct Recording(UnsafeCell<[u8; RECORD_CAPACITY]>);

// Written only by the armed thread while armed, read only after disarming.
unsafe impl Sync for Recording {}

static RECORDING: Recording = Recording(UnsafeCell::new([0; RECORD_CAPACITY]));
static RECORDED: AtomicUsize = AtomicUsize::new(0);
static OVERFLOWED: AtomicBool = AtomicBool::new(false);
static SERIAL: Mutex<()> = Mutex::new(());

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

struct RecordingAllocator;

unsafe impl GlobalAlloc for RecordingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    // The default `realloc` frees the old block through `dealloc`, so blocks
    // left behind by growth are recorded too.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.try_with(Cell::get).unwrap_or(false) {
            let start = RECORDED.load(Ordering::Relaxed);
            let end = start + 4 + layout.size();
            if end <= RECORD_CAPACITY {
                let base = RECORDING.0.get().cast::<u8>();
                unsafe {
                    base.add(start)
                        .cast::<[u8; 4]>()
                        .write_unaligned((layout.size() as u32).to_le_bytes());
                    std::ptr::copy_nonoverlapping(ptr, base.add(start + 4), layout.size());
                }
                RECORDED.store(end, Ordering::Relaxed);
            } else {
                OVERFLOWED.store(true, Ordering::Relaxed);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: RecordingAllocator = RecordingAllocator;

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Run `f` and return its result with a copy of every block it freed.
fn freed_by<R>(f: impl FnOnce() -> R) -> (R, Vec<Vec<u8>>) {
    RECORDED.store(0, Ordering::Relaxed);
    OVERFLOWED.store(false, Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    let result = f();
    ARMED.with(|armed| armed.set(false));
    assert!(
        !OVERFLOWED.load(Ordering::Relaxed),
        "freed blocks exceeded the recording buffer"
    );
    let len = RECORDED.load(Ordering::Relaxed);
    let recorded = unsafe { std::slice::from_raw_parts(RECORDING.0.get().cast::<u8>(), len) };
    let mut blocks = Vec::new();
    let mut at = 0;
    while at < len {
        let size = u32::from_le_bytes(recorded[at..at + 4].try_into().unwrap()) as usize;
        blocks.push(recorded[at + 4..at + 4 + size].to_vec());
        at += 4 + size;
    }
    (result, blocks)
}

/// Whether `block` holds 16 consecutive bytes of `secret`.
fn holds(block: &[u8], secret: &[u8]) -> bool {
    assert!(secret.len() >= 16, "secret is too short to search for");
    secret
        .windows(16)
        .any(|needle| block.windows(16).any(|window| window == needle))
}

/// Fail if any freed block holds part of a secret.
fn assert_no_residue(freed: &[Vec<u8>], secrets: &[(&str, &[u8])]) {
    let mut found = Vec::new();
    for (name, secret) in secrets {
        for block in freed {
            if holds(block, secret) {
                found.push(format!("{name} in a freed {}-byte block", block.len()));
            }
        }
    }
    assert!(found.is_empty(), "secret residue: {found:?}");
}

fn pseudo_random<const N: usize>(seed: u64) -> [u8; N] {
    let mut state = seed;
    let mut out = [0u8; N];
    for byte in &mut out {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state >> 24) as u8;
    }
    out
}

#[test]
fn token_encrypt_frees_no_plaintext() {
    let _serial = serial();
    let key: [u8; 64] = pseudo_random(1);
    let plaintext: [u8; 100] = pseudo_random(2);

    let (token, freed) = freed_by(|| token::encrypt(&plaintext, &key).unwrap());

    assert_no_residue(&freed, &[("plaintext", &plaintext)]);
    assert_eq!(
        &Zeroizing::new(token::decrypt(&token, &key).unwrap())[..],
        &plaintext[..]
    );
}

#[test]
fn token_decrypt_frees_no_plaintext() {
    let _serial = serial();
    let key: [u8; 64] = pseudo_random(3);
    let plaintext: [u8; 100] = pseudo_random(4);
    let token = token::encrypt(&plaintext, &key).unwrap();

    let ((), freed) = freed_by(|| {
        let decrypted = Zeroizing::new(token::decrypt(&token, &key).unwrap());
        assert_eq!(&decrypted[..], &plaintext[..]);
    });

    assert_no_residue(&freed, &[("plaintext", &plaintext)]);
}

#[test]
fn token_decrypt_wipes_an_authenticated_plaintext_with_bad_padding() {
    let _serial = serial();
    let key: [u8; 64] = pseudo_random(5);
    let mut plaintext: [u8; 64] = pseudo_random(6);
    plaintext[63] = 0;
    let iv = [0x24u8; 16];
    let mut token = iv.to_vec();
    token.extend_from_slice(&aes_cbc::encrypt(&key[32..], &iv, &plaintext).unwrap());
    let mac = hmac::hmac_sha256(&key[..32], &token);
    token.extend_from_slice(&mac);

    let (result, freed) = freed_by(|| token::decrypt(&token, &key));

    assert!(matches!(
        result,
        Err(token::TokenError::AuthenticationFailed)
    ));
    assert_no_residue(&freed, &[("plaintext", &plaintext[..63])]);
}

#[test]
fn aes_cbc_encrypt_with_a_bad_key_frees_no_plaintext() {
    let _serial = serial();
    let plaintext: [u8; 64] = pseudo_random(7);

    let (result, freed) = freed_by(|| aes_cbc::encrypt(&[0x11; 24], &[0x22; 16], &plaintext));

    assert!(matches!(
        result,
        Err(aes_cbc::AesCbcError::InvalidKeyLength(24))
    ));
    assert_no_residue(&freed, &[("plaintext", &plaintext)]);
}

#[test]
fn derive_key_64_frees_no_key() {
    let _serial = serial();
    let shared: [u8; 32] = pseudo_random(8);
    let salt: [u8; 16] = pseudo_random(9);
    let expected = Zeroizing::new(hkdf::hkdf_sha256(64, &shared, Some(&salt), None).unwrap());

    let (derived, freed): (Zeroizing<[u8; 64]>, _) =
        freed_by(|| hkdf::derive_key_64(&shared, &salt).unwrap());

    assert_eq!(&derived[..], &expected[..]);
    assert_no_residue(&freed, &[("derived key", &expected)]);
}
