use thiserror::Error;

#[derive(Debug, Error)]
pub enum RatkeyError {
    #[error("no hardware token found")]
    NoDevice,

    #[error("hardware token disconnected")]
    Disconnected,

    #[error("PIN verification failed ({remaining} attempts remaining)")]
    PinFailed { remaining: u8 },

    /// PIN retries are exhausted. A valid PUK can set a new PIN without
    /// erasing keys; destructive PIV reset is the fallback when recovery is
    /// unavailable.
    #[error("PIN locked; a valid PUK can set a new PIN without erasing keys")]
    PinLocked,

    #[error("PIV recovery code failed ({remaining} attempts remaining)")]
    PukFailed { remaining: u8 },

    /// PUK retries are exhausted. It can no longer recover the PIN; restoring
    /// PIV recovery requires a destructive reset. An otherwise valid PIN may
    /// still work until its own retry counter is exhausted.
    #[error("PIV recovery counter locked; a working PIN may still be usable. Resetting PIV erases user keys")]
    PukLocked,

    #[error("PIV reset requires both retry counters to be blocked")]
    ResetRequiresBlockedPinAndPuk,

    #[error("PIN required — call verify_pin() first")]
    PinRequired,

    #[error("touch required on hardware token")]
    TouchRequired,

    #[error("PIV slot 0x{slot:02X} has no key")]
    EmptySlot { slot: u8 },

    #[error("PIV slot 0x{slot:02X} already contains a key")]
    SlotOccupied { slot: u8 },

    #[error("unsupported device: {0}")]
    UnsupportedDevice(String),

    #[error("firmware version {found} does not meet minimum {required}")]
    FirmwareVersion { required: String, found: String },

    #[error("key mismatch: hardware public key does not match .hwid file")]
    KeyMismatch,

    #[error("management key authentication failed")]
    ManagementAuthFailed,

    #[cfg(feature = "hardware")]
    #[error("PC/SC error: {0}")]
    Pcsc(#[from] pcsc::Error),

    /// ISO 7816-4 status word (SW1/SW2) returned by the card.
    #[error("APDU error: SW={sw1:02X}{sw2:02X}")]
    Apdu { sw1: u8, sw2: u8 },

    #[error("invalid .hwid file: {0}")]
    InvalidHwid(String),

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("ECDH failed: {0}")]
    EcdhFailed(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
