//! Device classification (always available) + PC/SC reader enumeration (behind `hardware`).

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// "yubikey5" or "nitrokey3".
    pub device_type: String,
    pub reader_name: String,
    pub serial: Option<u32>,
    pub firmware: Option<String>,
    /// Slot 9A occupied.
    pub has_signing_key: bool,
    /// Slot 9D occupied.
    pub has_encryption_key: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    YubiKey5,
    Nitrokey3,
    Unknown,
}

impl DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceType::YubiKey5 => "yubikey5",
            DeviceType::Nitrokey3 => "nitrokey3",
            DeviceType::Unknown => "unknown",
        }
    }
}

/// YubiKey readers contain "Yubico" / "YubiKey"; Nitrokey 3 contains "Nitrokey".
pub fn detect_device_type(reader_name: &str) -> DeviceType {
    let lower = reader_name.to_lowercase();
    if lower.contains("yubico") || lower.contains("yubikey") {
        DeviceType::YubiKey5
    } else if lower.contains("nitrokey") {
        DeviceType::Nitrokey3
    } else {
        DeviceType::Unknown
    }
}

#[cfg(feature = "hardware")]
use crate::error::RatkeyError;
#[cfg(feature = "hardware")]
use pcsc::{Card, Context, Protocols, Scope, ShareMode};
#[cfg(feature = "hardware")]
use tracing::{debug, info, warn};

#[cfg(feature = "hardware")]
pub fn list_readers() -> Result<Vec<String>, RatkeyError> {
    let ctx = Context::establish(Scope::User)?;

    let mut reader_buf = vec![0u8; 4096];
    let readers = match ctx.list_readers(&mut reader_buf) {
        Ok(readers) => readers,
        Err(pcsc::Error::NoReadersAvailable) => {
            return Ok(Vec::new());
        }
        Err(e) => return Err(e.into()),
    };

    let names: Vec<String> = readers.map(|r| r.to_string_lossy().to_string()).collect();

    Ok(names)
}

#[cfg(feature = "hardware")]
pub fn detect_devices() -> Result<Vec<DeviceInfo>, RatkeyError> {
    let readers = list_readers()?;
    let mut devices = Vec::new();

    for reader_name in &readers {
        let device_type = detect_device_type(reader_name);
        if device_type == DeviceType::Unknown {
            debug!("skipping non-RATKEY reader: {}", reader_name);
            continue;
        }

        info!(
            "found potential device: {} ({})",
            reader_name,
            device_type.as_str()
        );

        match try_connect_piv(reader_name) {
            Ok(info) => {
                devices.push(DeviceInfo {
                    device_type: device_type.as_str().to_string(),
                    reader_name: reader_name.clone(),
                    serial: info.serial,
                    firmware: info.firmware,
                    has_signing_key: info.has_signing_key,
                    has_encryption_key: info.has_encryption_key,
                });
            }
            Err(e) => {
                warn!("failed to connect to {}: {}", reader_name, e);
            }
        }
    }

    Ok(devices)
}

#[cfg(feature = "hardware")]
fn try_connect_piv(reader_name: &str) -> Result<DeviceInfo, RatkeyError> {
    use crate::apdu;

    let ctx = Context::establish(Scope::User)?;

    let reader = std::ffi::CString::new(reader_name)
        .map_err(|_| RatkeyError::UnsupportedDevice(reader_name.to_string()))?;

    let card = ctx.connect(&reader, ShareMode::Shared, Protocols::ANY)?;

    let select_cmd = apdu::select_piv();
    let mut response_buf = vec![0u8; 256];
    let response = card.transmit(&select_cmd, &mut response_buf)?;
    apdu::check_response(response)?;

    debug!("PIV applet selected on {}", reader_name);

    let device_type = detect_device_type(reader_name);

    // GET METADATA success = slot occupied. Errors treated as empty so partially
    // provisioned tokens still detect.
    let meta_9a_cmd = apdu::get_metadata(apdu::SLOT_AUTHENTICATION);
    let mut meta_buf = vec![0u8; 256];
    let has_signing = match card.transmit(&meta_9a_cmd, &mut meta_buf) {
        Ok(resp) => apdu::check_response(resp).is_ok(),
        Err(_) => false,
    };

    let meta_9d_cmd = apdu::get_metadata(apdu::SLOT_KEY_MANAGEMENT);
    let mut meta_buf2 = vec![0u8; 256];
    let has_encryption = match card.transmit(&meta_9d_cmd, &mut meta_buf2) {
        Ok(resp) => apdu::check_response(resp).is_ok(),
        Err(_) => false,
    };

    let (serial, firmware) = read_identity(&card, device_type);

    Ok(DeviceInfo {
        device_type: device_type.as_str().to_string(),
        reader_name: reader_name.to_string(),
        serial,
        firmware,
        has_signing_key: has_signing,
        has_encryption_key: has_encryption,
    })
}

/// Best-effort serial/firmware read. Yubico proprietary INS — Nitrokey 3 returns (None, None).
/// APDU errors are tolerated; never fails a connection.
#[cfg(feature = "hardware")]
pub(crate) fn read_identity(card: &Card, device_type: DeviceType) -> (Option<u32>, Option<String>) {
    use crate::apdu;

    if device_type != DeviceType::YubiKey5 {
        return (None, None);
    }

    let mut buf = vec![0u8; 256];

    let serial = card
        .transmit(&apdu::get_serial(), &mut buf)
        .ok()
        .and_then(|resp| apdu::check_response(resp).ok().map(<[u8]>::to_vec))
        .and_then(|data| apdu::parse_serial_response(&data).ok());

    let firmware = card
        .transmit(&apdu::get_version(), &mut buf)
        .ok()
        .and_then(|resp| apdu::check_response(resp).ok().map(<[u8]>::to_vec))
        .and_then(|data| apdu::parse_version_response(&data).ok())
        .map(|(maj, min, patch)| format!("{maj}.{min}.{patch}"));

    (serial, firmware)
}
