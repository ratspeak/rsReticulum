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

    pub fn unblock_pin(&mut self, puk: &str, new_pin: &str) -> Result<(), RatkeyError> {
        let resp = self.transport.transmit(&apdu::reset_retry(puk, new_pin))?;
        match apdu::check_response(&resp) {
            Ok(_) => {
                self.pin_cache.cache(new_pin);
                Ok(())
            }
            Err(RatkeyError::PinFailed { remaining }) => Err(RatkeyError::PukFailed { remaining }),
            Err(RatkeyError::PinLocked) => Err(RatkeyError::PukLocked),
            Err(other) => Err(other),
        }
    }

    pub fn reset_piv(&mut self) -> Result<(), RatkeyError> {
        let resp = self.transport.transmit(&apdu::reset_piv())?;
        match apdu::check_response(&resp) {
            Ok(_) => {
                self.pin_cache.clear();
                Ok(())
            }
            Err(RatkeyError::Apdu {
                sw1: 0x69,
                sw2: 0x85,
            }) => Err(RatkeyError::ResetRequiresBlockedPinAndPuk),
            Err(other) => Err(other),
        }
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

    /// Import an off-device Ed25519 key (recoverable provisioning / restore).
    /// Requires prior `authenticate_management_key`.
    pub fn import_ed25519(
        &mut self,
        slot: u8,
        private_key: &[u8; 32],
        pin_policy: Option<u8>,
        touch_policy: Option<u8>,
    ) -> Result<(), RatkeyError> {
        let resp = self.transport.transmit(&apdu::import_ed25519(
            slot,
            private_key,
            pin_policy,
            touch_policy,
        ))?;
        apdu::check_response(&resp)?;
        Ok(())
    }

    /// Import an off-device X25519 key. Requires prior `authenticate_management_key`.
    pub fn import_x25519(
        &mut self,
        slot: u8,
        private_key: &[u8; 32],
        pin_policy: Option<u8>,
        touch_policy: Option<u8>,
    ) -> Result<(), RatkeyError> {
        let resp = self.transport.transmit(&apdu::import_x25519(
            slot,
            private_key,
            pin_policy,
            touch_policy,
        ))?;
        apdu::check_response(&resp)?;
        Ok(())
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

    /// Device attestation (slot F9) intermediate certificate, unwrapped to raw DER.
    /// This is the issuer of the per-slot certs returned by [`Self::attest_key`].
    pub fn read_attestation_cert(&mut self) -> Result<Vec<u8>, RatkeyError> {
        let cmd = apdu::get_data(apdu::SLOT_ATTESTATION)
            .ok_or(RatkeyError::EmptySlot { slot: apdu::SLOT_ATTESTATION })?;
        let resp = self.transport.transmit(&cmd)?;
        let data = apdu::check_response(&resp)?;
        apdu::parse_certificate_object(data).ok_or_else(|| {
            RatkeyError::InvalidHwid("device attestation cert (F9) not found in response".into())
        })
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

    /// Authenticate the PIV management key (slot 9B) via witness/challenge mutual
    /// auth — required before on-device key generation. The algorithm is read
    /// from the card (YubiKey 5.7 default: AES-192).
    pub fn authenticate_management_key(&mut self, key: &[u8]) -> Result<(), RatkeyError> {
        let meta = self.read_metadata(apdu::SLOT_CARD_MANAGEMENT)?;
        let alg = apdu::parse_metadata_algorithm(&meta)?;
        let block = crate::mgmt::block_len(alg).ok_or_else(|| {
            RatkeyError::UnsupportedDevice(format!(
                "unsupported management-key algorithm 0x{alg:02X}"
            ))
        })?;

        // Step 1: get the card's encrypted witness, decrypt it with the key.
        let resp = self.transport.transmit(&apdu::auth_witness_request(alg))?;
        let witness = apdu::parse_auth_witness(apdu::check_response(&resp)?)?;
        let decrypted = crate::mgmt::ecb_decrypt(alg, key, &witness)?;

        // Step 2: prove the witness + send our own challenge. A wrong key is
        // rejected here with an APDU status (not the mutual check below).
        let challenge = rns_crypto::random::random_bytes(block);
        let resp = self
            .transport
            .transmit(&apdu::auth_witness_response(alg, &decrypted, &challenge))?;
        let data = apdu::check_response(&resp).map_err(|_| RatkeyError::ManagementAuthFailed)?;
        let encrypted = apdu::parse_auth_response(data)?;

        // Step 3: mutual check — the card must have encrypted our challenge.
        if crate::mgmt::ecb_encrypt(alg, key, &challenge)? != encrypted {
            return Err(RatkeyError::ManagementAuthFailed);
        }
        Ok(())
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
