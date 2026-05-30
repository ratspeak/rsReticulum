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
        let initial = transmit_once(card, command)?;
        super::chain_response(command, initial, |apdu| transmit_once(card, apdu))
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

/// ISO 7816-4 response chaining, factored out of the PC/SC transport so it is
/// testable without a card. `initial` is the first response (data‖SW1‖SW2);
/// `transmit` sends a follow-up APDU and returns its raw response.
/// - `61 xx`: more data available — fetch it with GET RESPONSE and append.
/// - `6C xx`: wrong Le — resend `command` with the card's expected Le. Assumes
///   `command` carries no Le of its own (true for our case-3 reads); a command
///   that already has an Le would be malformed here.
///
/// Large reads (e.g. GET DATA on a ~1 KB attestation cert) arrive as `61 xx`;
/// without this every such read would be truncated to the first ≤256 bytes.
// Only the `hardware` transport calls this; the unit tests exercise it always.
#[cfg_attr(not(feature = "hardware"), allow(dead_code))]
pub(crate) fn chain_response(
    command: &[u8],
    initial: Vec<u8>,
    mut transmit: impl FnMut(&[u8]) -> Result<Vec<u8>, RatkeyError>,
) -> Result<Vec<u8>, RatkeyError> {
    let mut data = initial;
    // Bounded against a misbehaving card that never returns a terminal SW.
    for _ in 0..64 {
        if data.len() < 2 {
            break;
        }
        let (sw1, sw2) = (data[data.len() - 2], data[data.len() - 1]);
        if sw1 == 0x61 {
            data.truncate(data.len() - 2); // drop interim SW; keep the data
            let get_response = [0x00, 0xC0, 0x00, 0x00, sw2]; // sw2 = bytes left (0 = 256)
            data.extend_from_slice(&transmit(&get_response)?);
        } else if sw1 == 0x6C {
            let mut retry = command.to_vec();
            retry.push(sw2);
            data = transmit(&retry)?;
        } else {
            break;
        }
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_on_terminal_sw() {
        let out = chain_response(&[], vec![0x01, 0x02, 0x90, 0x00], |_| {
            panic!("no follow-up expected")
        })
        .unwrap();
        assert_eq!(out, vec![0x01, 0x02, 0x90, 0x00]);
    }

    #[test]
    fn appends_get_response_on_61() {
        let mut calls = 0;
        let out = chain_response(&[0x00, 0xCB, 0x3F, 0xFF], vec![0xAA, 0xBB, 0x61, 0x02], |apdu| {
            calls += 1;
            assert_eq!(apdu, &[0x00, 0xC0, 0x00, 0x00, 0x02]); // GET RESPONSE, Le=2
            Ok(vec![0xCC, 0xDD, 0x90, 0x00])
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(out, vec![0xAA, 0xBB, 0xCC, 0xDD, 0x90, 0x00]);
    }

    #[test]
    fn chains_multiple_61() {
        let mut step = 0;
        let out = chain_response(&[0x00], vec![0x01, 0x61, 0x00], |_| {
            step += 1;
            if step == 1 {
                Ok(vec![0x02, 0x61, 0x00]) // still more
            } else {
                Ok(vec![0x03, 0x90, 0x00]) // done
            }
        })
        .unwrap();
        assert_eq!(step, 2);
        assert_eq!(out, vec![0x01, 0x02, 0x03, 0x90, 0x00]);
    }

    #[test]
    fn resends_with_le_on_6c() {
        let out = chain_response(&[0x00, 0xCB, 0x3F, 0xFF], vec![0x6C, 0x05], |apdu| {
            assert_eq!(apdu, &[0x00, 0xCB, 0x3F, 0xFF, 0x05]); // original + Le=5
            Ok(vec![0xDE, 0xAD, 0x90, 0x00])
        })
        .unwrap();
        assert_eq!(out, vec![0xDE, 0xAD, 0x90, 0x00]);
    }
}
