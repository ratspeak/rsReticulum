//! Shared by the secret-residue test binaries. A recording allocator copies
//! every block the calling thread frees while a check runs; each check then
//! searches those copies for its secrets.
#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, UnsafeCell};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

const RECORD_CAPACITY: usize = 8 << 20;

struct Recording(UnsafeCell<[u8; RECORD_CAPACITY]>);

// Written only by the armed thread while armed, read only after disarming.
unsafe impl Sync for Recording {}

static RECORDING: Recording = Recording(UnsafeCell::new([0; RECORD_CAPACITY]));
static RECORDED: AtomicUsize = AtomicUsize::new(0);
static OVERFLOWED: AtomicBool = AtomicBool::new(false);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

struct RecordingAllocator;

fn armed() -> bool {
    ARMED.try_with(Cell::get).unwrap_or(false)
}

unsafe impl GlobalAlloc for RecordingAllocator {
    // Blocks handed out while armed start zeroed, so a recorded block holds
    // only what was written during the check, never a reused block's old bytes.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !armed() {
            return unsafe { System.alloc(layout) };
        }
        PEAK.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    // The default `realloc` frees the old block through `dealloc`, so blocks
    // left behind by growth are recorded too.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if armed() {
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

pub fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub struct Freed {
    pub blocks: Vec<Vec<u8>>,
    pub peak_allocation: usize,
}

/// Run `f` and return its result with a copy of every block it freed.
pub fn freed_by<R>(f: impl FnOnce() -> R) -> (R, Freed) {
    RECORDED.store(0, Ordering::Relaxed);
    OVERFLOWED.store(false, Ordering::Relaxed);
    PEAK.store(0, Ordering::Relaxed);
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
    let freed = Freed {
        blocks,
        peak_allocation: PEAK.load(Ordering::Relaxed),
    };
    (result, freed)
}

/// Whether `block` holds 16 consecutive bytes of `secret`.
pub fn holds(block: &[u8], secret: &[u8]) -> bool {
    !find(&[block.to_vec()], &[secret]).is_empty()
}

/// For each block holding 16 consecutive bytes of any of `secrets`: its
/// length and the indexes of the secrets it holds.
pub fn find(blocks: &[Vec<u8>], secrets: &[&[u8]]) -> Vec<(usize, Vec<usize>)> {
    let mut windows: HashMap<&[u8], Vec<usize>> = HashMap::new();
    for (index, secret) in secrets.iter().enumerate() {
        assert!(secret.len() >= 16, "secret is too short to search for");
        for window in secret.windows(16) {
            let owners = windows.entry(window).or_default();
            if owners.last() != Some(&index) {
                owners.push(index);
            }
        }
    }
    let mut found = Vec::new();
    for block in blocks {
        let mut held: Vec<usize> = block
            .windows(16)
            .filter_map(|window| windows.get(window))
            .flatten()
            .copied()
            .collect();
        held.sort_unstable();
        held.dedup();
        if !held.is_empty() {
            found.push((block.len(), held));
        }
    }
    found
}

/// Fail if any freed block holds part of a secret.
pub fn assert_no_residue(freed: &Freed, secrets: &[(&str, &[u8])]) {
    let values: Vec<&[u8]> = secrets.iter().map(|(_, secret)| *secret).collect();
    let mut found = Vec::new();
    for (len, held) in find(&freed.blocks, &values) {
        for index in held {
            found.push(format!("{} in a freed {len}-byte block", secrets[index].0));
        }
    }
    assert!(found.is_empty(), "secret residue: {found:?}");
}

pub fn pseudo_random<const N: usize>(seed: u64) -> [u8; N] {
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
