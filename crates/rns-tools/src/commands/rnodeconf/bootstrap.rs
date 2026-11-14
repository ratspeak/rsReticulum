//! Upstream `rnodeconf` EEPROM bootstrap (`--rom`, and the provisioning step
//! of `--flash` and `--autoinstall`) and `--eeprom-wipe`.

use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rns_interface::rnode;

use super::session::RNode;
use super::{
    ParsedEeprom, eeprom, firmware, graceful_exit, log, model, open_serial, out, parse_eeprom,
    py_fromhex, py_int, py_os_error, rnodeconf_root,
};

/// Python's error for indexing the missing signature upstream leaves at `None`.
const NO_SIGNATURE: &str = "'NoneType' object is not subscriptable";

/// Upstream `--eeprom-wipe`, taken right after the device probe.
pub fn wipe(rnode: &mut RNode) -> Result<ExitCode, String> {
    log("WARNING: EEPROM is being wiped! Power down device NOW if you do not want this!");
    rnode.wipe_eeprom()?;
    if rnode.platform != Some(model::PLATFORM_NRF52) {
        rnode.hard_reset()?;
    }
    Ok(graceful_exit(rnode, 0))
}

/// Firmware the device was just flashed with, whose hash bootstrap stores
/// (upstream `wants_fw_provision`).
pub struct FirmwareProvision {
    pub fw_filename: String,
    pub selected_version: String,
}

/// Upstream's inputs to the `args.rom` block.
pub struct Bootstrap<'a> {
    pub product: Option<&'a str>,
    pub model: Option<&'a str>,
    pub hwrev: Option<i64>,
    pub autoinstall: bool,
    /// Upstream global `mapped_product`: `PRODUCT_RNODE` unless autoinstall chose one.
    pub mapped_product: u8,
    /// Upstream global `mapped_model`, set only by autoinstall.
    pub mapped_model: Option<u8>,
    pub firmware: Option<FirmwareProvision>,
    /// Upstream `rnode_port`, reopened for manual-reset boards.
    pub port_path: &'a str,
}

/// Upstream `args.rom` block. `Err` is an exception upstream raises (exit 1).
pub fn bootstrap(
    rnode: &mut RNode,
    request: &Bootstrap,
    provisioned: bool,
    signature_valid: bool,
) -> Result<ExitCode, String> {
    if (provisioned && !request.autoinstall) || signature_valid {
        log("EEPROM bootstrap was requested, but a valid EEPROM was already present.");
        log("No changes are being made.");
        return Ok(graceful_exit(rnode, 0));
    }
    if request.autoinstall {
        log("Clearing old EEPROM, this will take about 15 seconds...");
        rnode.wipe_eeprom()?;
    }
    match rnode.platform {
        Some(model::PLATFORM_ESP32) => {
            log("Waiting for ESP32 reset...");
            rnode.pump(Duration::from_secs(6))?;
        }
        Some(model::PLATFORM_NRF52) => {
            rnode.close();
            log("Waiting for NRF52 reset...");
            std::thread::sleep(Duration::from_secs(18));
            if let Some(code) = reattach_nrf52(rnode) {
                return Ok(code);
            }
        }
        _ => rnode.pump(Duration::from_secs(3))?,
    }

    let root = rnodeconf_root()?;
    let firmware_dir = root.join("firmware");
    let counter_path = firmware_dir.join("serial.counter");
    let counter = match read_counter(&counter_path) {
        Ok(counter) => counter,
        Err(error) => {
            log("Could not create device serial number, exiting");
            log(error);
            return Ok(graceful_exit(rnode, 0));
        }
    };
    let serialno = counter + 1;

    let mut mapped_product = request.mapped_product;
    if let Some(product) = request.product
        && let Some(code) = hex_code(product)?
    {
        // Upstream's named product codes ("03", "10", "f0", "e0") equal their hex value.
        mapped_product = code;
    }
    let (model, selected_model) = match request.mapped_model {
        Some(mapped) => (Some(model::normalize_eeprom_model(mapped)), Some(mapped)),
        None => {
            let text = request
                .model
                .ok_or("object of type 'NoneType' has no len()")?;
            // Upstream's named model codes equal their hex value too.
            let model = hex_code(text)?;
            (model, model)
        }
    };
    let hwrev = request
        .hwrev
        .filter(|hwrev| (1..256).contains(hwrev))
        .map(|hwrev| hwrev as u8);

    let (Some(model), Some(hwrev), true) = (model, hwrev, serialno > 0) else {
        log("Invalid data specified, cancelling EEPROM write");
        return Ok(graceful_exit(rnode, 0));
    };
    let written = Written {
        product: mapped_product,
        model,
        hwrev,
        serialno,
        selected_model,
    };
    match write_and_validate(rnode, request, &written, &firmware_dir, &counter_path) {
        Err(error) => {
            log("An error occurred while writing EEPROM. The contained exception was:");
            log(&error);
            Err(error)
        }
        ok => ok,
    }
}

struct Written {
    product: u8,
    model: u8,
    hwrev: u8,
    serialno: i128,
    selected_model: Option<u8>,
}

/// The `try` block of upstream's bootstrap: everything it raises is logged.
fn write_and_validate(
    rnode: &mut RNode,
    request: &Bootstrap,
    written: &Written,
    firmware_dir: &Path,
    counter_path: &Path,
) -> Result<ExitCode, String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let time_bytes = u32::try_from(timestamp)
        .map_err(|_| "'I' format requires 0 <= number <= 4294967295".to_string())?
        .to_be_bytes();
    let serial_bytes = u32::try_from(written.serialno)
        .map_err(|_| "'I' format requires 0 <= number <= 4294967295".to_string())?
        .to_be_bytes();
    fs::create_dir_all(firmware_dir).map_err(|error| py_os_error(&error, firmware_dir))?;
    fs::write(counter_path, written.serialno.to_string())
        .map_err(|error| py_os_error(&error, counter_path))?;

    let mut info = vec![written.product, written.model, written.hwrev];
    info.extend_from_slice(&serial_bytes);
    info.extend_from_slice(&time_bytes);
    info.extend_from_slice(&eeprom::md5_digest(&info));

    log("Loading signing key...");
    let key_path = super::trust::signing_key_path(&rnodeconf_root()?);
    if !key_path.is_file() {
        log("No signing key found");
        return Ok(graceful_exit(rnode, 0));
    }
    let signature = fs::read(&key_path)
        .map_err(|error| py_os_error(&error, &key_path))
        .and_then(|key| super::trust::sign_eeprom_checksum(&key, &info[eeprom::ADDR_CHKSUM..]));
    let signature = match signature {
        Ok(signature) => Some(signature),
        Err(error) => {
            log("Error while signing EEPROM");
            log(error);
            None
        }
    };

    let manual = written
        .selected_model
        .is_some_and(|m| model::MANUAL_FLASH_MODELS.contains(&m));
    if manual {
        rnode.close();
        log("");
        log("Please reset the board by momentarily pressing the RESET button.");
        log("Hit enter when this is done.");
        rnode.wait_for_enter()?;
        std::thread::sleep(Duration::from_millis(2500));
        let port = open_serial(request.port_path).map_err(|error| error.to_string())?;
        *rnode = RNode::new(port, request.port_path.to_string());
    }

    log("Bootstrapping device EEPROM...");
    let nrf52 = rnode.platform == Some(model::PLATFORM_NRF52);
    let Some(signature) = signature else {
        let pace = if nrf52 { NRF52_WRITE_PACE } else { WRITE_PACE };
        write_paced(rnode, info.iter().copied().enumerate(), pace)?;
        return Err(NO_SIGNATURE.to_string());
    };
    info.extend_from_slice(&signature);
    if nrf52 {
        if !write_info_nrf52(rnode, &info)? {
            log("EEPROM was written, but validation failed. Check your settings.");
            return Ok(graceful_exit(rnode, 0));
        }
    } else {
        write_paced(rnode, info.iter().copied().enumerate(), WRITE_PACE)?;
    }
    rnode.write_eeprom(eeprom::ADDR_INFO_LOCK, eeprom::INFO_LOCK_BYTE)?;
    if nrf52 {
        rnode.pump(Duration::from_secs(3))?;
    }
    log("EEPROM written! Validating...");

    if let Some(provision) = request.firmware.as_ref() {
        let partition_hash = firmware_partition_hash(rnode.platform, provision)?;
        if let Some(hash) = partition_hash {
            rnode.pump(Duration::from_millis(750))?;
            log("Setting firmware checksum...");
            rnode.send(rnode::CMD_FW_HASH, &hash)?;
        }
    }

    match rnode.platform {
        Some(model::PLATFORM_ESP32) => {
            rnode.hard_reset()?;
            log("Waiting for ESP32 reset...");
            rnode.pump(Duration::from_secs(7))?;
            let slow = [
                model::MODEL_AC,
                model::MODEL_A6,
                model::MODEL_A1,
                model::MODEL_AA,
                model::MODEL_A5,
            ];
            if written.selected_model.is_some_and(|m| slow.contains(&m)) {
                rnode.pump(Duration::from_secs(5))?;
            }
        }
        Some(model::PLATFORM_NRF52) => {
            // Upstream waits here, or macOS fails to set the firmware hash.
            if cfg!(target_os = "macos") {
                rnode.pump(Duration::from_secs(5))?;
            }
            rnode.hard_reset()?;
            rnode.close();
            log("Waiting for NRF52 reset...");
            std::thread::sleep(Duration::from_secs(20));
            if let Some(code) = reattach_nrf52(rnode) {
                return Ok(code);
            }
        }
        _ => rnode.hard_reset()?,
    }

    let provisioned = if manual {
        rnode.close();
        log("");
        log("Please reset the board by momentarily pressing the RESET button.");
        log("Hit enter when this is done.");
        rnode.wait_for_enter()?;
        true
    } else {
        rnode.download_eeprom()?;
        let Some(image) = rnode.eeprom.clone() else {
            log("Could not download EEPROM from device. Is a valid firmware installed?");
            return Ok(graceful_exit(rnode, 0));
        };
        match parse_eeprom(&image, &rnode.name) {
            ParsedEeprom::Device(device) => device.is_some(),
            ParsedEeprom::ChecksumMismatch => return Ok(graceful_exit(rnode, 0)),
        }
    };
    if !provisioned {
        log("EEPROM was written, but validation failed. Check your settings.");
        return Ok(graceful_exit(rnode, 0));
    }
    log("EEPROM Bootstrapping successful!");
    if !manual {
        rnode.hard_reset()?;
    }
    if request.autoinstall {
        for line in AUTOINSTALL_COMPLETE {
            out(*line);
        }
        super::print_donation_block();
        out("");
    }
    let device_db = firmware_dir.join("device_db");
    let backup = fs::create_dir_all(&device_db)
        .and_then(|()| fs::File::create(device_db.join(hex::encode(serial_bytes))))
        .map_err(|_| ())
        .and_then(|mut file| {
            // Upstream opens the file before writing, so a missing image leaves it empty.
            let image = rnode.eeprom.as_deref().ok_or(())?;
            std::io::Write::write_all(&mut file, image).map_err(|_| ())
        });
    if backup.is_err() {
        log("WARNING: Could not backup device EEPROM to disk");
    }
    Ok(graceful_exit(rnode, 0))
}

const WRITE_PACE: Duration = Duration::from_millis(6);
const NRF52_WRITE_PACE: Duration = Duration::from_millis(150);

fn write_paced(
    rnode: &mut RNode,
    bytes: impl IntoIterator<Item = (usize, u8)>,
    pace: Duration,
) -> Result<(), String> {
    for (address, value) in bytes {
        rnode.write_eeprom(address, value)?;
        rnode.pump(pace)?;
    }
    Ok(())
}

/// nRF52 flash-backed EEPROM drops bytes sent 6 ms apart (upstream's pace), so
/// write slower and read back before the lock. `false`: bytes never matched.
fn write_info_nrf52(rnode: &mut RNode, info: &[u8]) -> Result<bool, String> {
    let rnode = std::cell::RefCell::new(rnode);
    eeprom::write_with_read_back(
        info,
        |address, value| {
            write_paced(
                &mut rnode.borrow_mut(),
                [(address, value)],
                NRF52_WRITE_PACE,
            )
        },
        || {
            let mut rnode = rnode.borrow_mut();
            rnode.download_eeprom()?;
            Ok(rnode.eeprom.clone())
        },
    )
}

/// Upstream finds the nRF52 again by its USB serial number after a reset.
/// `Some` is upstream's `exit()` when the new port cannot be opened.
fn reattach_nrf52(rnode: &mut RNode) -> Option<ExitCode> {
    let Some(path) = port_with_usb_serial(rnode.usb_serial_id.as_deref()) else {
        log("Could not detect new port for NRF52...");
        return None;
    };
    match open_serial(&path) {
        Ok(port) => {
            rnode.reopen(port, path);
            None
        }
        Err(error) => {
            log("Could not open the specified serial port. The contained exception was:");
            log(error.to_string());
            Some(ExitCode::SUCCESS)
        }
    }
}

/// USB serial number of the port at `path`, as upstream reads it from `list_ports`.
pub fn usb_serial_number(path: &str) -> Option<String> {
    serialport::available_ports()
        .ok()?
        .into_iter()
        .find(|port| port.port_name == path)
        .and_then(|port| match port.port_type {
            serialport::SerialPortType::UsbPort(info) => info.serial_number,
            _ => None,
        })
}

/// Upstream compares `None` too and so takes any port without a USB serial
/// number; a device without one is never matched here.
fn port_with_usb_serial(serial: Option<&str>) -> Option<String> {
    let serial = serial?;
    serialport::available_ports()
        .ok()?
        .into_iter()
        .find(|port| match &port.port_type {
            serialport::SerialPortType::UsbPort(info) => {
                info.serial_number.as_deref() == Some(serial)
            }
            _ => false,
        })
        .map(|port| port.port_name)
}

/// Upstream reads `serial.counter` with `int()`, or starts from 0.
fn read_counter(path: &Path) -> Result<i128, String> {
    if !path.is_file() {
        return Ok(0);
    }
    let text = fs::read(path).map_err(|error| py_os_error(&error, path))?;
    py_int(&String::from_utf8_lossy(&text))
}

/// Upstream `ord(bytes.fromhex(text))` for a two-character value; other lengths are ignored.
fn hex_code(text: &str) -> Result<Option<u8>, String> {
    if text.chars().count() != 2 {
        return Ok(None);
    }
    match py_fromhex(text).as_deref() {
        Some([code]) => Ok(Some(*code)),
        Some(_) => Err("ord() expected a character, but string of length 0 found".to_string()),
        None => Err("non-hexadecimal number found in fromhex() arg".to_string()),
    }
}

/// Upstream's partition hash for the firmware it just flashed.
fn firmware_partition_hash(
    platform: Option<u8>,
    provision: &FirmwareProvision,
) -> Result<Option<Vec<u8>>, String> {
    let root = rnodeconf_root()?;
    if provision.fw_filename == "extracted_rnode_firmware.zip" {
        let path = root
            .join("extracted")
            .join("extracted_rnode_firmware.version");
        let bytes = fs::read(&path).map_err(|error| py_os_error(&error, &path))?;
        let text = String::from_utf8(bytes).map_err(|error| error.to_string())?;
        let field = text
            .split_whitespace()
            .nth(1)
            .ok_or("list index out of range")?;
        return py_fromhex(field)
            .map(Some)
            .ok_or_else(|| "non-hexadecimal number found in fromhex() arg".to_string());
    }
    let path = root
        .join("update")
        .join(&provision.selected_version)
        .join(provision.fw_filename.replace(".zip", ".bin"));
    Ok(partition_hash(platform, &path).map(|hash| hash.to_vec()))
}

/// Upstream `get_partition_hash`: the image's embedded hash on ESP32 and AVR,
/// the file's SHA-256 on nRF52.
pub fn partition_hash(platform: Option<u8>, path: &Path) -> Option<[u8; 32]> {
    let platform = platform?;
    if ![
        model::PLATFORM_ESP32,
        model::PLATFORM_AVR,
        model::PLATFORM_NRF52,
    ]
    .contains(&platform)
    {
        return None;
    }
    match fs::read(path) {
        Ok(data) => firmware::partition_hash(platform, &data),
        Err(error) => {
            log("Could not calculate firmware partition hash. The contained exception was:");
            log(py_os_error(&error, path));
            None
        }
    }
}

const AUTOINSTALL_COMPLETE: &[&str] = &[
    "",
    "RNode Firmware autoinstallation complete!",
    "",
    "To use your device with Reticulum, read the documetation at:",
    "",
    "https://markqvist.github.io/Reticulum/manual/gettingstartedfast.html",
    "",
    "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *",
    "                              Important!            ",
    "",
    "ESP32-based RNodes are created with the RNode Bootstrap Console on-board.",
    "",
    "This repository is hosted directly on the RNode, and contains a wealth of",
    "information, software and tools.",
    "",
    "The RNode Bootstrap Console also contains everything needed to build",
    "and replicate RNodes, including detailed build recipes, 3D-printable",
    "cases, and copies of the source code for both the RNode Firmware,",
    "Reticulum and other utilities.",
    "",
    "To activate the RNode Bootstrap Console, power up your RNode and hold",
    "down the user button for 10+ seconds, then release. The RNode will now",
    "reboot into console mode, and activate a WiFi access point for you to",
    "connect to. The console is then reachable at: http://10.0.0.1",
    "",
    "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *",
    "",
    "Thank you for using this utility! Please help the project by",
    "contributing code and reporting bugs, or by donating!",
    "",
    "Your contributions and donations directly further the realisation",
    "of truly open, free and resilient communications systems.",
    "",
];
