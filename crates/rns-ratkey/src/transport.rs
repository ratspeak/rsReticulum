//! Transport seam for PIV. The PIV protocol logic lives in `PivSession`; this
//! trait is the only platform-specific part: APDU bytes in, response bytes out.
//! Desktop PC/SC ships here behind the `hardware` feature. Mobile NFC/USB
//! transports live in the application layer and implement the same trait.

use crate::error::RatkeyError;

pub trait PivTransport {
    /// Send one ISO 7816-4 APDU; return the full response including SW1/SW2.
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, RatkeyError>;

    /// Cheap liveness probe — token still present and responding.
    fn is_connected(&self) -> bool;
}

#[cfg(feature = "hardware")]
pub use pcsc_transport::PcscTransport;

#[cfg(feature = "hardware")]
mod pcsc_transport {
    use pcsc::{Context, Protocols, Scope, ShareMode};
    use tracing::{debug, warn};

    use super::PivTransport;
    use crate::apdu;
    use crate::detect::{self, detect_device_type};
    use crate::error::RatkeyError;
    use crate::session::DeviceMeta;

    const MAX_RESPONSE: usize = 4096;

    /// Real PIV transport over PC/SC (YubiKey 5, Nitrokey 3). Requires a PC/SC
    /// daemon: macOS CryptoTokenKit / Linux pcscd / Windows WinSCard.
    pub struct PcscTransport {
        card: pcsc::Card,
    }

    impl PcscTransport {
        /// Connect to the first detected RATKEY token.
        pub fn connect() -> Result<(Self, DeviceMeta), RatkeyError> {
            let devices = detect::detect_devices()?;
            let device = devices.first().ok_or(RatkeyError::NoDevice)?;
            Self::connect_reader(&device.reader_name)
        }

        /// Connect to a specific PC/SC reader by name.
        pub fn connect_reader(reader_name: &str) -> Result<(Self, DeviceMeta), RatkeyError> {
            let ctx = Context::establish(Scope::User)?;
            let reader = std::ffi::CString::new(reader_name)
                .map_err(|_| RatkeyError::UnsupportedDevice(reader_name.to_string()))?;
            let card = ctx.connect(&reader, ShareMode::Shared, Protocols::ANY)?;

            let resp = transmit_card(&card, &apdu::select_piv())?;
            apdu::check_response(&resp)?;

            let device_type = detect_device_type(reader_name);
            debug!(
                "PIV session established with {} ({})",
                reader_name,
                device_type.as_str()
            );

            let (serial, firmware) = detect::read_identity(&card, device_type);

            Ok((
                Self { card },
                DeviceMeta {
                    device_type,
                    serial,
                    firmware,
                },
            ))
        }
    }

    impl PivTransport for PcscTransport {
        fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, RatkeyError> {
            transmit_card(&self.card, apdu)
        }

        fn is_connected(&self) -> bool {
            // Attestation slot (F9) is present on any provisioned token.
            let cmd = apdu::get_metadata(apdu::SLOT_ATTESTATION);
            let mut buf = vec![0u8; 256];
            self.card.transmit(&cmd, &mut buf).is_ok()
        }
    }

    fn transmit_card(card: &pcsc::Card, command: &[u8]) -> Result<Vec<u8>, RatkeyError> {
        let mut data = transmit_once(card, command)?;
        // ISO 7816-4 response chaining. Large reads (e.g. GET DATA on a ~1 KB cert)
        // come back as `61 xx` — more data, fetch it with GET RESPONSE — and `6C xx`
        // means resend with the card's expected Le. Accumulate into one response.
        let mut guard = 0;
        while data.len() >= 2 {
            guard += 1;
            if guard > 64 {
                warn!("APDU response chaining exceeded bound");
                break;
            }
            let (sw1, sw2) = (data[data.len() - 2], data[data.len() - 1]);
            if sw1 == 0x61 {
                data.truncate(data.len() - 2); // drop interim SW; keep the data
                let get_response = [0x00, 0xC0, 0x00, 0x00, sw2]; // sw2 = bytes left (0 = 256)
                data.extend_from_slice(&transmit_once(card, &get_response)?);
            } else if sw1 == 0x6C {
                let mut retry = command.to_vec(); // wrong Le: resend with the exact Le
                retry.push(sw2);
                data = transmit_once(card, &retry)?;
            } else {
                break;
            }
        }
        Ok(data)
    }

    fn transmit_once(card: &pcsc::Card, command: &[u8]) -> Result<Vec<u8>, RatkeyError> {
        let mut response_buf = vec![0u8; MAX_RESPONSE];
        let response = card.transmit(command, &mut response_buf).map_err(|e| {
            warn!("PC/SC transmit failed: {}", e);
            RatkeyError::Disconnected
        })?;
        Ok(response.to_vec())
    }
}
