//! Transport-agnostic PIV session. Every PIV operation is built on `apdu` plus a
//! `PivTransport`; the transport is the only platform-specific part (see `transport`).
//! `hardware` feature adds the PC/SC `connect()` entry points.

use crate::apdu;
use crate::detect::DeviceType;
use crate::error::RatkeyError;
use crate::pin::PinCache;
use crate::transport::PivTransport;

/// Device identity captured once at connect time; no per-operation cost.
pub struct DeviceMeta {
    pub device_type: DeviceType,
    pub serial: Option<u32>,
    pub firmware: Option<String>,
}

pub struct PivSession<T: PivTransport> {
    transport: T,
    device_type: DeviceType,
    serial: Option<u32>,
    firmware: Option<String>,
    pin_cache: PinCache,
}

impl<T: PivTransport> PivSession<T> {
    pub fn new(transport: T, meta: DeviceMeta) -> Self {
        Self {
            transport,
            device_type: meta.device_type,
            serial: meta.serial,
            firmware: meta.firmware,
            pin_cache: PinCache::default_timeout(),
        }
    }

    pub fn device_type(&self) -> DeviceType {
        self.device_type
    }

    pub fn serial(&self) -> Option<u32> {
        self.serial
    }

    pub fn firmware(&self) -> Option<&str> {
        self.firmware.as_deref()
    }

    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }

    /// Re-locks the card: re-selects the PIV applet (resetting the on-card PIN
    /// verification) and clears the cached PIN, so the next private-key op needs
    /// a fresh `verify_pin`. This is the mechanism behind the app-side session
    /// timeout / lock-on-quit.
    pub fn lock(&mut self) -> Result<(), RatkeyError> {
        let resp = self.transport.transmit(&apdu::select_piv())?;
        apdu::check_response(&resp)?;
        self.pin_cache.clear();
        Ok(())
    }

    pub fn verify_pin(&mut self, pin: &str) -> Result<(), RatkeyError> {
        let resp = self.transport.transmit(&apdu::verify_pin(pin))?;
        apdu::check_response(&resp)?;
        self.pin_cache.cache(pin);
        Ok(())
    }

    pub fn change_pin(&mut self, old_pin: &str, new_pin: &str) -> Result<(), RatkeyError> {
        let resp = self.transport.transmit(&apdu::change_pin(old_pin, new_pin))?;
        apdu::check_response(&resp)?;
        self.pin_cache.cache(new_pin);
        Ok(())
    }

    pub fn generate_ed25519(
        &mut self,
        slot: u8,
        pin_policy: Option<u8>,
        touch_policy: Option<u8>,
    ) -> Result<[u8; 32], RatkeyError> {
        let resp = self.transport.transmit(&apdu::generate_key(
            slot,
            apdu::ALG_ED25519,
            pin_policy,
            touch_policy,
        ))?;
        let data = apdu::check_response(&resp)?;
        apdu::parse_generate_response(data)
    }

    pub fn generate_x25519(
        &mut self,
        slot: u8,
        pin_policy: Option<u8>,
        touch_policy: Option<u8>,
    ) -> Result<[u8; 32], RatkeyError> {
        let resp = self.transport.transmit(&apdu::generate_key(
            slot,
            apdu::ALG_X25519,
            pin_policy,
            touch_policy,
        ))?;
        let data = apdu::check_response(&resp)?;
        apdu::parse_generate_response(data)
    }

    pub fn sign_ed25519(&mut self, slot: u8, message: &[u8]) -> Result<[u8; 64], RatkeyError> {
        let resp = self.transport.transmit(&apdu::sign_ed25519(slot, message))?;
        let data = apdu::check_response(&resp)?;
        apdu::parse_sign_response(data)
    }

    pub fn ecdh_x25519(&mut self, slot: u8, peer_pub: &[u8; 32]) -> Result<[u8; 32], RatkeyError> {
        let resp = self.transport.transmit(&apdu::ecdh_x25519(slot, peer_pub))?;
        let data = apdu::check_response(&resp)?;
        apdu::parse_ecdh_response(data)
    }

    /// Returns DER-encoded X.509 attestation certificate.
    pub fn attest_key(&mut self, slot: u8) -> Result<Vec<u8>, RatkeyError> {
        let resp = self.transport.transmit(&apdu::attest_key(slot))?;
        Ok(apdu::check_response(&resp)?.to_vec())
    }

    pub fn read_certificate(&mut self, slot: u8) -> Result<Vec<u8>, RatkeyError> {
        let cmd = apdu::get_data(slot).ok_or(RatkeyError::EmptySlot { slot })?;
        let resp = self.transport.transmit(&cmd)?;
        Ok(apdu::check_response(&resp)?.to_vec())
    }

    /// Returns raw GET METADATA TLV bytes.
    pub fn read_metadata(&mut self, slot: u8) -> Result<Vec<u8>, RatkeyError> {
        let resp = self.transport.transmit(&apdu::get_metadata(slot))?;
        Ok(apdu::check_response(&resp)?.to_vec())
    }

    /// Reads the slot's 32-byte public key from GET METADATA. The metadata byte
    /// layout is pending confirmation against a real device — see
    /// `apdu::parse_metadata_public_key`. Yubico 5.3+ only (Nitrokey 3 has no
    /// GET METADATA).
    pub fn read_public_key(&mut self, slot: u8) -> Result<[u8; 32], RatkeyError> {
        let metadata = self.read_metadata(slot)?;
        apdu::parse_metadata_public_key(&metadata)
    }
}

/// PC/SC convenience alias; `connect()` lives on this monomorphization.
#[cfg(feature = "hardware")]
pub type PcscPivSession = PivSession<crate::transport::PcscTransport>;

#[cfg(feature = "hardware")]
impl PivSession<crate::transport::PcscTransport> {
    /// Connect to the first detected token over PC/SC.
    pub fn connect() -> Result<Self, RatkeyError> {
        let (transport, meta) = crate::transport::PcscTransport::connect()?;
        Ok(Self::new(transport, meta))
    }

    /// Connect to a specific PC/SC reader by name.
    pub fn connect_reader(reader_name: &str) -> Result<Self, RatkeyError> {
        let (transport, meta) = crate::transport::PcscTransport::connect_reader(reader_name)?;
        Ok(Self::new(transport, meta))
    }
}
