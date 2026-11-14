//! rnodeconf-rs - RNode configuration and firmware utility.
//!
//! Device probe, info, configuration summary, EEPROM dump and backup, device
//! settings, signing and trust, firmware hash readout and TNC/normal startup
//! mode, EEPROM wipe and bootstrap, and firmware update, flashing and
//! extraction follow upstream `rnodeconf`. Autoinstall is disabled in this build.

use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{CommandFactory, Parser};
use rns_interface::{rnode, rnode_admin};
use rns_tools::RS_RETICULUM_VERSION;

#[path = "rnodeconf/bootstrap.rs"]
mod bootstrap;
#[allow(dead_code)]
#[path = "rnodeconf/eeprom.rs"]
mod eeprom;
#[allow(dead_code)]
#[path = "rnodeconf/firmware.rs"]
mod firmware;
#[allow(dead_code)]
#[path = "rnodeconf/flash.rs"]
mod flash;
#[path = "rnodeconf/install.rs"]
mod install;
#[allow(dead_code)]
#[path = "rnodeconf/model.rs"]
mod model;
#[path = "rnodeconf/plan.rs"]
mod plan;
#[path = "rnodeconf/session.rs"]
mod session;
#[path = "rnodeconf/trust.rs"]
mod trust;

use session::{RNode, py_float, py_round};

/// Upstream `rnodeconf` program version, separate from the RNS version.
const RNODECONF_VERSION: &str = "2.5.0";

#[derive(Parser, Debug)]
#[command(
    name = "rnodeconf-rs",
    about = "RNode Configuration and firmware utility. This program allows you to change various settings and startup modes of RNode. It can also install, flash and update the firmware on supported devices.",
    disable_version_flag = true,
    infer_long_args = true
)]
struct Args {
    /// Show device info
    #[arg(short = 'i', long)]
    info: bool,
    /// Automatic installation on various supported devices
    #[arg(short = 'a', long)]
    autoinstall: bool,
    /// Update firmware to the latest version
    #[arg(short = 'u', long)]
    update: bool,
    /// Update to specified firmware even if version matches or is older than installed version
    #[arg(short = 'U', long = "force-update")]
    force_update: bool,
    /// Use a specific firmware version for update or autoinstall
    #[arg(long = "fw-version", value_name = "version")]
    fw_version: Option<String>,
    /// Use an alternate firmware download URL
    #[arg(long = "fw-url", value_name = "url")]
    fw_url: Option<String>,
    /// Don't check for firmware updates online
    #[arg(long)]
    nocheck: bool,
    /// Extract firmware from connected RNode for later use
    #[arg(short = 'e', long)]
    extract: bool,
    /// Use the extracted firmware for autoinstallation or update
    #[arg(short = 'E', long = "use-extracted")]
    use_extracted: bool,
    /// Clear locally cached firmware files
    #[arg(short = 'C', long = "clear-cache")]
    clear_cache: bool,
    /// Set specific baud rate when flashing device. Default is 921600
    #[arg(
        long = "baud-flash",
        value_name = "baud_flash",
        default_value = "921600"
    )]
    baud_flash: String,

    /// Switch device to normal mode
    #[arg(short = 'N', long)]
    normal: bool,
    /// Switch device to TNC mode
    #[arg(short = 'T', long)]
    tnc: bool,

    /// Turn device bluetooth on
    #[arg(short = 'b', long = "bluetooth-on")]
    bluetooth_on: bool,
    /// Turn device bluetooth off
    #[arg(short = 'B', long = "bluetooth-off")]
    bluetooth_off: bool,
    /// Put device into bluetooth pairing mode
    #[arg(short = 'p', long = "bluetooth-pair")]
    bluetooth_pair: bool,

    /// Set WiFi mode (OFF, AP or STATION)
    #[arg(short = 'w', long = "wifi", value_name = "mode")]
    wifi: Option<String>,
    /// Set WiFi channel
    #[arg(long, value_name = "channel")]
    channel: Option<String>,
    /// Set WiFi SSID (NONE to delete)
    #[arg(long, value_name = "ssid")]
    ssid: Option<String>,
    /// Set WiFi PSK (NONE to delete)
    #[arg(long, value_name = "psk")]
    psk: Option<String>,
    /// Display stored WiFi PSK
    #[arg(long = "show-psk")]
    show_psk: bool,
    /// Set static WiFi IP address (NONE for DHCP)
    #[arg(long, value_name = "ip")]
    ip: Option<String>,
    /// Set static WiFi network mask (NONE for DHCP)
    #[arg(long, value_name = "nm")]
    nm: Option<String>,

    /// Set display intensity (0-255)
    #[arg(
        short = 'D',
        long = "display",
        value_name = "i",
        allow_negative_numbers = true
    )]
    display: Option<i64>,
    /// Set display timeout in seconds, 0 to disable
    #[arg(
        short = 't',
        long = "timeout",
        value_name = "s",
        allow_negative_numbers = true
    )]
    timeout: Option<i64>,
    /// Set display rotation, valid values are 0 through 3
    #[arg(
        short = 'R',
        long = "rotation",
        value_name = "rotation",
        allow_negative_numbers = true
    )]
    rotation: Option<i64>,
    /// Set display address as hex byte (00 - FF)
    #[arg(long = "display-addr", value_name = "byte")]
    display_addr: Option<String>,
    /// Start display reconditioning
    #[arg(long = "recondition-display")]
    recondition_display: bool,
    /// Set NeoPixel intensity (0-255)
    #[arg(long = "np", value_name = "i", allow_negative_numbers = true)]
    neopixel: Option<i64>,

    /// Frequency in Hz for TNC mode
    #[arg(long = "freq", value_name = "Hz", allow_negative_numbers = true)]
    freq: Option<i64>,
    /// Bandwidth in Hz for TNC mode
    #[arg(long = "bw", value_name = "Hz", allow_negative_numbers = true)]
    bandwidth: Option<i64>,
    /// TX power in dBm for TNC mode
    #[arg(long = "txp", value_name = "dBm", allow_negative_numbers = true)]
    tx_power: Option<i64>,
    /// Spreading factor for TNC mode (7 - 12)
    #[arg(long = "sf", value_name = "factor", allow_negative_numbers = true)]
    spreading_factor: Option<i64>,
    /// Coding rate for TNC mode (5 - 8)
    #[arg(long = "cr", value_name = "rate", allow_negative_numbers = true)]
    coding_rate: Option<i64>,

    /// Enable interference avoidance
    #[arg(short = 'x', long = "ia-enable")]
    ia_enable: bool,
    /// Disable interference avoidance
    #[arg(short = 'X', long = "ia-disable")]
    ia_disable: bool,

    /// Print device configuration
    #[arg(short = 'c', long = "config")]
    config: bool,

    /// Backup EEPROM to file
    #[arg(long = "eeprom-backup")]
    eeprom_backup: bool,
    /// Dump EEPROM to console
    #[arg(long = "eeprom-dump")]
    eeprom_dump: bool,
    /// Unlock and wipe EEPROM
    #[arg(long = "eeprom-wipe")]
    eeprom_wipe: bool,

    /// Display public part of signing key
    #[arg(short = 'P', long = "public")]
    public: bool,
    /// Public key to trust for device verification
    #[arg(long = "trust-key", value_name = "hexbytes")]
    trust_key: Option<String>,

    /// Print program version and exit
    #[arg(long)]
    version: bool,

    /// Flash firmware and bootstrap EEPROM
    #[arg(short = 'f', long)]
    flash: bool,
    /// Bootstrap EEPROM without flashing firmware
    #[arg(short = 'r', long)]
    rom: bool,
    /// Generate a new signing key and exit
    #[arg(short = 'k', long)]
    key: bool,
    /// Display public part of signing key
    #[arg(short = 'S', long)]
    sign: bool,
    /// Set installed firmware hash
    #[arg(short = 'H', long = "firmware-hash", value_name = "FIRMWARE_HASH")]
    firmware_hash: Option<String>,
    #[arg(short = 'K', long = "get-target-firmware-hash", hide = true)]
    get_target_firmware_hash: bool,
    #[arg(short = 'L', long = "get-firmware-hash", hide = true)]
    get_firmware_hash: bool,
    /// Platform specification for device bootstrap
    #[arg(long, value_name = "platform")]
    platform: Option<String>,
    /// Product specification for device bootstrap
    #[arg(long, value_name = "product")]
    product: Option<String>,
    /// Model code for device bootstrap
    #[arg(long, value_name = "model")]
    model: Option<String>,
    /// Hardware revision for device bootstrap
    #[arg(long, value_name = "revision", allow_negative_numbers = true)]
    hwrev: Option<i64>,

    /// serial port where RNode is attached
    port: Option<String>,
}

pub(crate) fn main() -> ExitCode {
    let mut args = Args::parse();
    if args.version {
        out(rns_tools::version_line(
            "rnodeconf-rs",
            RS_RETICULUM_VERSION,
            &[("rnodeconf", RNODECONF_VERSION)],
        ));
        return ExitCode::SUCCESS;
    }
    if args.clear_cache {
        log("Clearing local firmware cache...");
        match rnodeconf_cache_paths().and_then(|paths| clear_firmware_cache(&paths)) {
            Ok(()) => log("Done"),
            Err(e) => {
                eprintln!("rnodeconf-rs: {e}");
                return ExitCode::from(1);
            }
        }
        return ExitCode::SUCCESS;
    }
    if let Some(version) = args.fw_version.as_deref()
        && version.trim().parse::<f64>().is_err()
    {
        log(format!(
            "Selected version \"{version}\" does not appear to be a number."
        ));
        return ExitCode::SUCCESS;
    }
    if let Some(key) = args.trust_key.as_deref().filter(|key| !key.is_empty()) {
        return trust_key(key);
    }
    if let Some(message) = install::feature_refusal(&args) {
        eprintln!("rnodeconf-rs: {message}");
        return ExitCode::from(2);
    }
    if let Err(e) = install::use_extracted_warning(&args) {
        eprintln!("rnodeconf-rs: {e}");
        return ExitCode::from(1);
    }
    if args.extract {
        return install::extract(&args);
    }
    if let Some(message) = plan::refusal_without_port(&args) {
        eprintln!("rnodeconf-rs: {message}");
        return ExitCode::from(2);
    }
    if args.public {
        show_public_keys();
        return ExitCode::SUCCESS;
    }
    if args.key {
        return generate_keys();
    }
    let Some(port_path) = args.port.clone() else {
        out("");
        let _ = Args::command().print_help();
        out("");
        out("");
        return ExitCode::SUCCESS;
    };
    if args.flash {
        match install::flash(&args, &port_path) {
            Ok(rom) => args.rom = rom,
            Err(code) => return code,
        }
    }

    log(format!("Opening serial port {port_path}..."));
    let port = match open_serial(&port_path) {
        Ok(port) => port,
        Err(e) => {
            log("Could not open the specified serial port. The contained exception was:");
            log(e.to_string());
            return ExitCode::SUCCESS;
        }
    };
    let mut rnode = RNode::new(port, port_path.clone());
    rnode.usb_serial_id = bootstrap::usb_serial_number(&port_path);
    match run_device(rnode, &args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("rnodeconf-rs: {e}");
            ExitCode::from(1)
        }
    }
}

/// Upstream `rnode_open_serial`.
fn open_serial(path: &str) -> serialport::Result<Box<dyn serialport::SerialPort>> {
    rns_interface::serial::open_port(
        serialport::new(path, 115200).timeout(Duration::from_millis(100)),
    )
}

/// Upstream `print_donation_block`.
fn print_donation_block() {
    for line in [
        "  Ethereum  : 0x91C421DdfB8a30a49A71d63447ddb54cEBe3465E",
        "  Bitcoin   : bc1pgqgu8h8xvj4jtafslq396v7ju7hkgymyrzyqft4llfslz5vp99psqfk3a6",
        "  Monero    : 87HcDx6jRSkMQ9nPRd5K9hGGpZLn2s7vWETjMaVM5KfV4TD36NcYa8J8WSxhTSvBzzFpqDwp2fg5GX2moZ7VAP9QMZCZGET",
        "  Ko-Fi     : https://ko-fi.com/markqvist",
        "  LiberaPay : https://liberapay.com/reticulum",
        "",
        "  Info      : https://reticulum.network",
        "  Code      : https://github.com/markqvist",
    ] {
        out(line);
    }
}

/// Upstream `main()` from the device probe on, for the operations this build
/// supports. Errors are the cases where upstream raises an exception.
fn run_device(session: RNode, args: &Args) -> Result<ExitCode, String> {
    let mut session = session;
    let rnode = &mut session;
    if let Err(e) = rnode.device_probe() {
        log("Serial port opened, but RNode did not respond. Is a valid firmware installed?");
        out(e);
        return Ok(graceful_exit(rnode, 0));
    }
    if rnode.detected == Some(true) && (rnode.platform.is_none() || rnode.mcu.is_none()) {
        rnode.platform = Some(model::PLATFORM_AVR);
        rnode.mcu = Some(model::MCU_1284P);
    }

    if args.eeprom_wipe {
        return bootstrap::wipe(rnode);
    }

    log("Reading EEPROM...");
    rnode.download_eeprom()?;
    let Some(eeprom) = rnode.eeprom.clone() else {
        log("Could not download EEPROM from device. Is a valid firmware installed?");
        return Ok(graceful_exit(rnode, 0));
    };
    let device = match parse_eeprom(&eeprom, &rnode.name) {
        ParsedEeprom::Device(device) => device,
        ParsedEeprom::ChecksumMismatch => return Ok(graceful_exit(rnode, 0)),
    };
    // Upstream looks up the firmware file for every provisioned model and stops on an unknown one.
    if let Some(device) = device.as_ref()
        && model::model_info(device.model).is_none()
    {
        return Err(format!("unknown model code {}", device.model));
    }

    let (mut session, device, info) = if args.update {
        match install::update(session, args, device)? {
            install::UpdateStep::Exit(code) => return Ok(code),
            install::UpdateStep::Continue {
                rnode,
                info,
                device,
            } => (*rnode, device, info),
        }
    } else {
        (session, device, args.info)
    };
    let rnode = &mut session;

    if args.config {
        rnode.download_cfg_sector()?;
        for line in
            eeprom::device_configuration_lines(&eeprom, rnode.cfg_sector.as_deref(), args.show_psk)
        {
            out(line);
        }
        rnode.leave()?;
        return Ok(graceful_exit(rnode, 0));
    }

    if args.eeprom_dump {
        log("EEPROM contents:");
        log(rns_tools::format::hex_rep(&eeprom));
        return Ok(graceful_exit(rnode, 0));
    }

    if args.eeprom_backup {
        match write_eeprom_backup(&eeprom) {
            Ok(path) => log(format!("EEPROM backup written to: {path}")),
            Err(_) => {
                log("EEPROM was successfully downloaded from device,");
                log("but file could not be written to disk.");
            }
        }
        return Ok(graceful_exit(rnode, 0));
    }

    if let Some(code) = apply_device_settings(rnode, args)? {
        return Ok(code);
    }

    if info {
        let Some(device) = device.as_ref() else {
            log("EEPROM is invalid, no further information available");
            return Ok(graceful_exit(rnode, 0));
        };
        for line in device_info_lines(device, rnode)? {
            log(line);
        }
        out("");
        rnode.leave()?;
        return Ok(graceful_exit(rnode, 0));
    }

    if args.rom {
        let request = bootstrap::Bootstrap {
            product: args.product.as_deref(),
            model: args.model.as_deref(),
            hwrev: args.hwrev,
            autoinstall: args.autoinstall,
            mapped_product: model::PRODUCT_RNODE,
            mapped_model: None,
            firmware: None,
            port_path: &rnode.name.clone(),
        };
        let signature_valid = device.as_ref().is_some_and(|d| d.signature.valid);
        return bootstrap::bootstrap(rnode, &request, device.is_some(), signature_valid);
    }

    if args.sign {
        if device.is_none() {
            log("This device has not been provisioned yet, cannot create device signature");
            return Ok(graceful_exit(rnode, 79));
        }
        let signer = load_identity(&trust::device_key_path(&rnodeconf_root()?));
        match (rnode.device_hash, signer) {
            (None, _) => log("No device hash present, skipping device signing"),
            (Some(_), None) => {
                log("No device signer loaded, cannot sign device");
                return Ok(graceful_exit(rnode, 78));
            }
            (Some(hash), Some(signer)) => {
                let signature = trust::sign_device_hash(&signer, &hash)?;
                rnode.send_frame(&trust::device_signature_frame(&signature))?;
                log("Device signed");
            }
        }
    }

    if let Some(value) = args.firmware_hash.as_deref() {
        if device.is_none() {
            log("This device has not been provisioned yet, cannot set firmware hash");
            return Ok(graceful_exit(rnode, 77));
        }
        match py_fromhex(value).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) {
            Some(hash) => {
                rnode.send_frame(&trust::firmware_hash_frame(&hash))?;
                log("Firmware hash set");
            }
            None => {
                log("The provided value was not a valid SHA256 hash");
                return Ok(graceful_exit(rnode, 78));
            }
        }
    }

    for (wanted, label, hash) in [
        (
            args.get_target_firmware_hash,
            "target",
            rnode.firmware_hash_target.clone(),
        ),
        (
            args.get_firmware_hash,
            "actual",
            rnode.firmware_hash.clone(),
        ),
    ] {
        if !wanted {
            continue;
        }
        if device.is_none() {
            log("This device has not been provisioned yet, cannot get firmware hash");
            return Ok(ExitCode::from(77));
        }
        let hash =
            hash.ok_or_else(|| format!("the device did not report its {label} firmware hash"))?;
        log(format!(
            "The {label} firmware hash is: {}",
            hex::encode(hash)
        ));
    }

    if device.is_some() {
        if args.normal {
            rnode.set_normal_mode()?;
            log("Device set to normal (host-controlled) operating mode");
            return Ok(graceful_exit(rnode, 0));
        }
        if args.tnc {
            set_tnc_mode(rnode, args)?;
            return Ok(graceful_exit(rnode, 0));
        }
    } else {
        log("This device contains a valid firmware, but EEPROM is invalid.");
        log("Probably the device has not been initialised, or the EEPROM has been erased.");
        log("Please correctly initialise the device and try again!");
    }
    Ok(graceful_exit(rnode, 0))
}

/// Upstream's display, interference avoidance, NeoPixel, Bluetooth and Wi-Fi
/// setters, in its order. `Some` is an exit upstream takes inside this block.
/// One-byte values are KISS-escaped: upstream sends them raw, so 0xC0 and 0xDB
/// break their frames.
fn apply_device_settings(rnode: &mut RNode, args: &Args) -> Result<Option<ExitCode>, String> {
    let byte = |value: i64, max: i64| value.clamp(0, max) as u8;
    if let Some(value) = args.display {
        let di = byte(value, 255);
        log(format!("Setting display intensity to {di}"));
        rnode.send(rnode::CMD_DISP_INT, &[di])?;
    }
    if let Some(value) = args.timeout {
        let di = byte(value, 255);
        if di == 0 {
            log("Disabling display blanking");
        } else {
            log(format!("Setting display timeout to {di}"));
        }
        rnode.send(rnode::CMD_DISP_BLNK, &[di])?;
    }
    if let Some(value) = args.rotation {
        let dr = byte(value, 3);
        log(format!("Setting display rotation to {dr}"));
        rnode.send(rnode::CMD_DISP_ROT, &[dr])?;
    }
    if args.recondition_display {
        log("Starting display reconditioning");
        rnode.send(rnode::CMD_DISP_RCND, &[0x01])?;
    }
    if args.ia_enable {
        log("Enabling interference avoidance");
        rnode.send(rnode::CMD_DIS_IA, &[0x00])?;
    }
    if args.ia_disable {
        log("Disabling interference avoidance");
        rnode.send(rnode::CMD_DIS_IA, &[0x01])?;
    }
    if let Some(value) = args.neopixel {
        let di = byte(value, 255);
        log(format!("Setting NeoPixel intensity to {di}"));
        rnode.send(rnode::CMD_NP_INT, &[di])?;
    }
    if let Some(addr) = args.display_addr.as_deref() {
        let addr = addr.strip_prefix("0x").unwrap_or(addr);
        match py_fromhex(addr).as_deref() {
            Some(&[da]) => {
                log(format!("Setting display address to {da:02x}"));
                rnode.send(rnode::CMD_DISP_ADR, &[da])?;
                rnode.hard_reset()?;
                return Ok(Some(graceful_exit(rnode, 0)));
            }
            _ => log("Invalid display address specified"),
        }
    }
    if args.bluetooth_on {
        log("Enabling Bluetooth...");
        rnode.send(rnode::CMD_BT_CTRL, &[0x01])?;
        rnode.leave()?;
    }
    if args.bluetooth_off {
        log("Disabling Bluetooth...");
        rnode.send(rnode::CMD_BT_CTRL, &[0x00])?;
        rnode.leave()?;
    }
    if args.bluetooth_pair {
        log("Putting device into Bluetooth pairing mode. Press enter to exit when done.");
        rnode.send(rnode::CMD_BT_CTRL, &[0x02])?;
        rnode.wait_for_enter()?;
        rnode.leave()?;
    }

    let given = |value: &Option<String>| value.clone().filter(|value| !value.is_empty());
    let failed = |rnode: &mut RNode, what: &str, error: String| {
        out(format!("Could not set WiFi {what}: {error}"));
        Some(graceful_exit(rnode, 0))
    };
    if let Some(channel) = given(&args.channel) {
        log(format!("Setting WiFi channel to {channel}"));
        match py_int(&channel).ok().filter(|ch| (1..=14).contains(ch)) {
            Some(ch) => rnode.send_frame(&rnode_admin::wifi_channel_frame(ch as u8))?,
            None => return Ok(failed(rnode, "channel", "Invalid WiFi channel".into())),
        }
    }
    if let Some(ssid) = given(&args.ssid) {
        let ssid = if ssid.to_lowercase() == "none" {
            log("Deleting WiFi SSID");
            None
        } else {
            log(format!("Setting WiFi SSID to: {ssid}"));
            Some(ssid)
        };
        match rnode_admin::wifi_ssid_frame(ssid.as_deref()) {
            Some(frame) => rnode.send_frame(&frame)?,
            None => return Ok(failed(rnode, "SSID", "Invalid SSID length".into())),
        }
    }
    if let Some(psk) = given(&args.psk) {
        let psk = if psk.to_lowercase() == "none" {
            log("Deleting WiFi PSK");
            None
        } else {
            log("Setting WiFi PSK");
            Some(psk)
        };
        match rnode_admin::wifi_psk_frame(psk.as_deref()) {
            Some(frame) => rnode.send_frame(&frame)?,
            None => return Ok(failed(rnode, "PSK", "Invalid psk length".into())),
        }
    }
    for (value, what, command) in [
        (given(&args.ip), "IP", rnode::CMD_WIFI_IP),
        (given(&args.nm), "netmask", rnode::CMD_WIFI_NM),
    ] {
        let Some(value) = value else { continue };
        let address = if value.to_lowercase() == "none" {
            log(if command == rnode::CMD_WIFI_IP {
                "Setting WiFi IP to DHCP...".to_string()
            } else {
                "Deleting WiFi static netmask configuration...".to_string()
            });
            Ok([0; 4])
        } else {
            log(if command == rnode::CMD_WIFI_IP {
                format!("Setting WiFi static IP to: {value}")
            } else {
                format!("Setting WiFi static netmask to: {value}")
            });
            parse_wifi_address(&value)
        };
        match address {
            Ok(address) => rnode.send(command, &address)?,
            Err(error) => return Ok(failed(rnode, what, error)),
        }
    }
    if let Some(wifi) = given(&args.wifi) {
        let wifi = wifi.to_lowercase();
        let mode = if wifi.starts_with("sta") {
            log("Setting WiFi to station mode");
            rnode_admin::WifiMode::Station
        } else if wifi.starts_with("ap") {
            log("Setting WiFi to AP mode");
            rnode_admin::WifiMode::AccessPoint
        } else {
            log("Disabling WiFi...");
            rnode_admin::WifiMode::Off
        };
        rnode.send(rnode::CMD_WIFI_MODE, &[mode as u8])?;
    }
    Ok(None)
}

/// Upstream `set_wifi_ip` / `set_wifi_nm` address parsing and its messages.
fn parse_wifi_address(value: &str) -> Result<[u8; 4], String> {
    let octets: Vec<&str> = value.split('.').collect();
    if octets.len() != 4 {
        return Err("Invalid IP address length".to_string());
    }
    let mut address = [0u8; 4];
    for (slot, octet) in address.iter_mut().zip(octets) {
        let octet =
            py_int(octet).map_err(|error| format!("Could not decode IP address octet: {error}"))?;
        *slot = u8::try_from(octet)
            .map_err(|_| "Could not decode IP address octet: Invalid IP octet value".to_string())?;
    }
    Ok(address)
}

/// Python `int(text)` for base 10; the error is Python's message.
fn py_int(text: &str) -> Result<i128, String> {
    let error = || format!("invalid literal for int() with base 10: {}", py_repr(text));
    let trimmed = text.trim();
    let (negative, digits) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let bytes = digits.as_bytes();
    let well_formed = !bytes.is_empty()
        && bytes.first().is_some_and(u8::is_ascii_digit)
        && bytes.last().is_some_and(u8::is_ascii_digit)
        && bytes.iter().all(|b| b.is_ascii_digit() || *b == b'_')
        && !digits.contains("__");
    if !well_formed {
        return Err(error());
    }
    let magnitude = digits
        .chars()
        .filter(char::is_ascii_digit)
        .fold(0i128, |acc, d| {
            acc.saturating_mul(10)
                .saturating_add(i128::from(d as u8 - b'0'))
        });
    Ok(if negative { -magnitude } else { magnitude })
}

/// Python `bytes.fromhex`: hex digit pairs, ASCII whitespace allowed between bytes.
fn py_fromhex(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c.is_ascii_whitespace() {
            continue;
        }
        let high = c.to_digit(16)?;
        let low = chars.next()?.to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

/// Python `repr(str)` for the printable strings these messages quote.
fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python's `str(OSError)` for a failed file operation on `path`.
fn py_os_error(error: &std::io::Error, path: &Path) -> String {
    let text = error.to_string();
    match error.raw_os_error() {
        Some(code) => format!(
            "[Errno {code}] {}: {}",
            text.split(" (os error").next().unwrap_or(&text),
            py_repr(&path.display().to_string())
        ),
        None => text,
    }
}

/// Upstream `RNS.Identity.from_file`: `None`, with its log lines, on failure.
fn load_identity(path: &Path) -> Option<rns_identity::identity::Identity> {
    match fs::read(path) {
        Ok(bytes) => match trust::identity_from_private_key(&bytes) {
            Ok(identity) => Some(identity),
            Err(error) => {
                log(format!(
                    "Failed to load identity key, the contained exception was: {error}"
                ));
                None
            }
        },
        Err(error) => {
            log(format!(
                "Error while loading identity from {}",
                path.display()
            ));
            log(format!(
                "The contained exception was: {}",
                py_os_error(&error, path)
            ));
            None
        }
    }
}

/// Upstream `--trust-key`.
fn trust_key(key: &str) -> ExitCode {
    let Some(public_bytes) = py_fromhex(key) else {
        log("Invalid key data supplied");
        return ExitCode::SUCCESS;
    };
    let result = trust::check_public_key_der(&public_bytes).and_then(|()| {
        log(format!(
            "Trusting key: {}",
            hex::encode(rns_crypto::sha::sha256(&public_bytes))
        ));
        let root = rnodeconf_root()?;
        trust::write_trusted_key(&root, &public_bytes)
            .map(|_| ())
            .map_err(|error| py_os_error(&error, &trust::trusted_key_path(&root, &public_bytes)))
    });
    if let Err(error) = result {
        log("Could not create public key from supplied data. Check that the key format is valid.");
        log(error);
    }
    ExitCode::SUCCESS
}

/// Upstream `-P`.
fn show_public_keys() {
    let root = match rnodeconf_root() {
        Ok(root) => root,
        Err(error) => {
            log(error);
            return;
        }
    };
    let private_bytes = fs::read(trust::signing_key_path(&root)).ok();
    if private_bytes.is_none() {
        log("Could not load EEPROM signing key");
    }
    match trust::signing_public_key_der(private_bytes.as_deref()) {
        Ok(public) => {
            log("EEPROM Signing Public key:");
            log(hex::encode(public));
        }
        Err(error) => {
            log("Could not deserialize signing key");
            log(error);
        }
    }
    let signer = load_identity(&trust::device_key_path(&root));
    log("");
    log("Device Signing Public key:");
    match signer {
        Some(signer) => log(rns_tools::format::hex_rep(&signer.get_public_key()[32..])),
        None => log("Could not load device signing key"),
    }
}

/// Upstream `-k`: a device signing identity and an EEPROM signing key, each
/// created only when absent. Exits 81 and 82 are upstream's intent; upstream
/// never reaches them because `Identity.to_file` and `from_file` swallow errors.
fn generate_keys() -> ExitCode {
    let root = match rnodeconf_root() {
        Ok(root) => root,
        Err(error) => {
            log(error);
            return ExitCode::SUCCESS;
        }
    };
    let firmware_dir = root.join("firmware");
    let device_key = trust::device_key_path(&root);
    if !device_key.is_file() {
        log("Generating a new device signing key...");
        let _ = fs::create_dir_all(&firmware_dir);
        if let Err(error) = rns_identity::identity::Identity::new().to_file(&device_key) {
            log(format!(
                "Could not create new device signing key at {}. The contained exception was:",
                device_key.display()
            ));
            log(error.to_string());
            log("Please ensure filesystem access and try again.");
            return ExitCode::from(81);
        }
        log(format!(
            "Device signing key written to {}",
            device_key.display()
        ));
    } else {
        let loaded = fs::read(&device_key)
            .map_err(|error| py_os_error(&error, &device_key))
            .and_then(|bytes| trust::identity_from_private_key(&bytes).map(|_| ()));
        if let Err(error) = loaded {
            log(format!(
                "Could not load device signing key from {}. The contained exception was:",
                device_key.display()
            ));
            log(error);
            log("Please restore or clear the key and try again.");
            return ExitCode::from(82);
        }
    }

    let signing_key = trust::signing_key_path(&root);
    if signing_key.is_file() {
        let _ = fs::create_dir_all(&firmware_dir);
        log("EEPROM Signing key already exists, not overwriting!");
        log("Manually delete this key to create a new one.");
        return ExitCode::SUCCESS;
    }
    log("Generating a new EEPROM signing key...");
    let (private_bytes, public_bytes) = match trust::generate_signing_key() {
        Ok(keys) => keys,
        Err(error) => {
            log(error);
            return ExitCode::SUCCESS;
        }
    };
    if fs::create_dir_all(&firmware_dir).is_err() || !firmware_dir.is_dir() {
        log("The firmware directory does not exist, can't write key!");
        return ExitCode::SUCCESS;
    }
    if let Err(error) = fs::write(&signing_key, &private_bytes) {
        log(py_os_error(&error, &signing_key));
        return ExitCode::SUCCESS;
    }
    log("Wrote signing key");
    log("Public key:");
    log(hex::encode(public_bytes));
    ExitCode::SUCCESS
}

/// Upstream `graceful_exit`: only Windows tells the device the host left.
fn graceful_exit(rnode: &mut RNode, code: u8) -> ExitCode {
    if cfg!(windows) {
        let _ = rnode.leave();
    }
    ExitCode::from(code)
}

fn set_tnc_mode(rnode: &mut RNode, args: &Args) -> Result<(), String> {
    let given = |value: Option<i64>| value.filter(|value| *value != 0);
    if [
        args.freq,
        args.bandwidth,
        args.tx_power,
        args.spreading_factor,
        args.coding_rate,
    ]
    .iter()
    .any(|value| given(*value).is_none())
    {
        log("Please input startup configuration:");
    }
    out("");
    let frequency = given(args.freq).map_or_else(|| prompt("Frequency in Hz:\t"), Ok)?;
    let bandwidth = given(args.bandwidth).map_or_else(|| prompt("Bandwidth in Hz:\t"), Ok)?;
    let tx_power = args
        .tx_power
        .filter(|txp| (0..=17).contains(txp))
        .map_or_else(|| prompt("TX Power in dBm:\t"), Ok)?;
    let spreading_factor =
        given(args.spreading_factor).map_or_else(|| prompt("Spreading factor:\t"), Ok)?;
    let coding_rate = given(args.coding_rate).map_or_else(|| prompt("Coding rate:\t\t"), Ok)?;
    out("");

    // initRadio, with the one-byte values escaped too (upstream sends them raw).
    rnode.send(rnode::CMD_FREQUENCY, &radio_word(frequency)?)?;
    rnode.send(rnode::CMD_BANDWIDTH, &radio_word(bandwidth)?)?;
    rnode.send(rnode::CMD_TXPOWER, &[radio_byte(tx_power)?])?;
    rnode.send(rnode::CMD_SF, &[radio_byte(spreading_factor)?])?;
    rnode.send(rnode::CMD_CR, &[radio_byte(coding_rate)?])?;
    rnode.send(rnode::CMD_RADIO_STATE, &[rnode::RADIO_STATE_ON])?;
    rnode.pump(Duration::from_millis(500))?;
    rnode.set_tnc_mode()?;
    log("Device set to TNC operating mode");
    rnode.pump(Duration::from_secs(1))
}

/// Upstream packs `value >> 24` unmasked, so it must fit in four bytes.
fn radio_word(value: i64) -> Result<[u8; 4], String> {
    u32::try_from(value)
        .map(u32::to_be_bytes)
        .map_err(|_| "bytes must be in range(0, 256)".to_string())
}

fn radio_byte(value: i64) -> Result<u8, String> {
    u8::try_from(value).map_err(|_| "bytes must be in range(0, 256)".to_string())
}

fn prompt(label: &str) -> Result<i64, String> {
    let mut stdout = std::io::stdout().lock();
    let _ = write!(stdout, "{label}");
    let _ = stdout.flush();
    drop(stdout);
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if read == 0 {
        return Err("EOF when reading a line".to_string());
    }
    line.trim().replace('_', "").parse().map_err(|_| {
        format!(
            "invalid literal for int() with base 10: '{}'",
            line.trim_end()
        )
    })
}

struct Device {
    product: u8,
    model: u8,
    hw_rev: u8,
    serialno: [u8; 4],
    made: u32,
    min_freq: u64,
    max_freq: u64,
    max_output: u8,
    signature: trust::SignatureCheck,
    configured: Option<eeprom::RadioConfig>,
}

enum ParsedEeprom {
    /// `None` is upstream's `provisioned = False`.
    Device(Option<Device>),
    ChecksumMismatch,
}

/// Upstream `RNode.parse_eeprom`, including its log output.
fn parse_eeprom(bytes: &[u8], port_name: &str) -> ParsedEeprom {
    if bytes.len() <= eeprom::ADDR_CONF_OK {
        log("Invalid EEPROM data, could not parse device EEPROM.");
        log("The contained exception was: index out of range");
        return ParsedEeprom::Device(None);
    }
    if bytes[eeprom::ADDR_INFO_LOCK] != eeprom::INFO_LOCK_BYTE {
        return ParsedEeprom::Device(None);
    }
    let model_code = bytes[eeprom::ADDR_MODEL];
    let (min_freq, max_freq, max_output) = match model::model_info(model_code) {
        Some(info) => (info.min_freq, info.max_freq, info.max_output),
        None => {
            log("Error: Model band and output power capabilities are unknown!");
            log(format!("The contained exception was: {model_code}"));
            (0, 0, 0)
        }
    };
    let checksum = &bytes[eeprom::ADDR_CHKSUM..eeprom::ADDR_CHKSUM + 16];
    if checksum != eeprom::md5_digest(&bytes[..eeprom::ADDR_CHKSUM]) {
        log("EEPROM checksum mismatch");
        return ParsedEeprom::ChecksumMismatch;
    }
    log("EEPROM checksum correct");
    let root = rnodeconf_root().ok();
    let signature = trust::validate_device_signature(
        &bytes[eeprom::ADDR_SIGNATURE..eeprom::ADDR_SIGNATURE + 128],
        checksum,
        root.as_deref(),
    );
    if signature.valid {
        log("Device signature validated");
    } else {
        log("Device signature validation failed");
        for line in UNVERIFIED_DEVICE_WARNING {
            out(*line);
        }
        out(format!("              rnodeconf {port_name} --autoinstall"));
        out("");
    }
    let image = eeprom::EepromImage::new(bytes.to_vec()).expect("length checked");
    let identity = image.identity();
    ParsedEeprom::Device(Some(Device {
        product: identity.product,
        model: model_code,
        hw_rev: identity.hw_rev,
        serialno: identity.serial.to_be_bytes(),
        made: identity.made,
        min_freq,
        max_freq,
        max_output,
        signature,
        configured: image.radio_config(),
    }))
}

const UNVERIFIED_DEVICE_WARNING: &[&str] = &[
    "     ",
    "     WARNING! This device is NOT verifiable and should NOT be trusted.",
    "     Someone could have added privacy-breaking or malicious code to it.",
    "     ",
    "     Please verify the signing key is present on this machine.",
    "     Autogenerated keys will not match another machine's signature.",
    "     ",
    "     Proceed at your own risk and responsibility! If you created this",
    "     device yourself, please read the documentation on how to sign your",
    "     device to avoid this warning.",
    "     ",
    "     Always use a firmware downloaded as binaries or compiled from source",
    "     from one of the following locations:",
    "     ",
    "        https://github.com/markqvist/rnode_firmware",
    "        https://github.com/liberatedsystems/RNode_Firmware_CE",
    "     ",
    "     You can reflash and bootstrap this device to a verifiable state",
    "     by using this utility. It is recommended to do so NOW!",
    "     ",
    "     To initialise this device to a verifiable state, please run:",
    "     ",
];

/// Upstream `--info` block, one entry per `RNS.log` call.
fn device_info_lines(device: &Device, rnode: &RNode) -> Result<Vec<String>, String> {
    let product = model::product_name(device.product)
        .ok_or_else(|| format!("KeyError: {}", device.product))?;
    let info =
        model::model_info(device.model).ok_or_else(|| format!("KeyError: {}", device.model))?;
    let signature = if !device.signature.valid {
        "Unverified".to_string()
    } else if device.signature.locally_signed {
        "Validated - Local signature".to_string()
    } else {
        format!(
            "Genuine board, vendor is {}",
            device.signature.vendor.as_deref().unwrap_or_default()
        )
    };
    let board = rnode
        .board
        .map(|board| format!(":{board:02x}"))
        .unwrap_or_default();
    let mut lines = vec![
        String::new(),
        "Device info:".to_string(),
        format!(
            "\tProduct            : {product} {} ({:02x}:{:02x}{board})",
            info.band, device.product, device.model
        ),
        format!("\tDevice signature   : {signature}"),
        format!(
            "\tFirmware version   : {}",
            rnode.version().unwrap_or_default()
        ),
        format!("\tHardware revision  : {}", device.hw_rev),
        format!(
            "\tSerial number      : {}",
            rns_tools::format::hex_rep(&device.serialno)
        ),
        format!("\tModem chip         : {}", info.modem),
        format!(
            "\tFrequency range    : {} MHz - {} MHz",
            py_float(device.min_freq as f64 / 1e6),
            py_float(device.max_freq as f64 / 1e6)
        ),
        format!("\tMax TX power       : {} dBm", device.max_output),
        format!(
            "\tManufactured       : {}",
            format_local_time(i64::from(device.made), "-", " ", ":")
        ),
    ];
    if let Some(conf) = device.configured.as_ref() {
        let sf = f64::from(conf.spreading_factor);
        let bandwidth_khz = f64::from(conf.bandwidth) / 1000.0;
        if conf.coding_rate == 0 || conf.bandwidth == 0 {
            return Err("the stored TNC configuration has no valid bitrate".to_string());
        }
        let bitrate =
            sf * ((4.0 / f64::from(conf.coding_rate)) / (2f64.powf(sf) / bandwidth_khz)) * 1000.0;
        let txp_mw = py_round(10f64.powf(f64::from(conf.tx_power) / 10.0), 3);
        lines.extend([
            String::new(),
            "\tDevice mode        : TNC".to_string(),
            format!(
                "\t  Frequency        : {} MHz",
                py_float(f64::from(conf.frequency) / 1_000_000.0)
            ),
            format!("\t  Bandwidth        : {} KHz", py_float(bandwidth_khz)),
            format!(
                "\t  TX power         : {} dBm ({} mW)",
                conf.tx_power,
                py_float(txp_mw)
            ),
            format!("\t  Spreading factor : {}", conf.spreading_factor),
            format!("\t  Coding rate      : {}", conf.coding_rate),
            format!(
                "\t  On-air bitrate   : {} kbps",
                py_float(py_round(bitrate / 1000.0, 2))
            ),
        ]);
    } else {
        lines.push("\tDevice mode        : Normal (host-controlled)".to_string());
    }
    Ok(lines)
}

/// Print a line, ignoring a closed stdout as upstream's logger does.
fn out(line: impl AsRef<str>) {
    let _ = writeln!(std::io::stdout().lock(), "{}", line.as_ref());
}

/// `RNS.log` with rnodeconf's compact `[%H:%M:%S]` format.
fn log(message: impl AsRef<str>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64);
    let [_, _, _, hour, minute, second] = local_time(now);
    out(format!(
        "[{hour:02}:{minute:02}:{second:02}] {}",
        message.as_ref()
    ));
}

fn format_local_time(secs: i64, date_sep: &str, mid: &str, time_sep: &str) -> String {
    let [year, month, day, hour, minute, second] = local_time(secs);
    format!(
        "{year:04}{date_sep}{month:02}{date_sep}{day:02}{mid}{hour:02}{time_sep}{minute:02}{time_sep}{second:02}"
    )
}

/// Local calendar time, as Python's `time.localtime`.
#[cfg(unix)]
fn local_time(secs: i64) -> [i64; 6] {
    let time = secs as nix::libc::time_t;
    let mut tm = std::mem::MaybeUninit::<nix::libc::tm>::zeroed();
    // SAFETY: both pointers are valid for the call; localtime_r is reentrant.
    let result = unsafe { nix::libc::localtime_r(&time, tm.as_mut_ptr()) };
    if result.is_null() {
        return utc_time(secs);
    }
    // SAFETY: localtime_r filled `tm` when it returned non-null.
    let tm = unsafe { tm.assume_init() };
    [
        i64::from(tm.tm_year) + 1900,
        i64::from(tm.tm_mon) + 1,
        i64::from(tm.tm_mday),
        i64::from(tm.tm_hour),
        i64::from(tm.tm_min),
        i64::from(tm.tm_sec),
    ]
}

#[cfg(not(unix))]
fn local_time(secs: i64) -> [i64; 6] {
    utc_time(secs)
}

fn utc_time(secs: i64) -> [i64; 6] {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    [year, month, day, rem / 3600, rem % 3600 / 60, rem % 60]
}

fn rnodeconf_cache_paths() -> Result<firmware::CachePaths, String> {
    Ok(firmware::CachePaths::new(rnodeconf_root()?))
}

fn rnodeconf_root() -> Result<PathBuf, String> {
    if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("rnodeconf"))
            .ok_or_else(|| "APPDATA is not set; cannot locate rnodeconf data directory".to_string())
    } else {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|path| path.join(".config").join("rnodeconf"))
            .ok_or_else(|| "HOME is not set; cannot locate rnodeconf data directory".to_string())
    }
}

/// Upstream removes only the downloaded firmware; extracted firmware stays.
fn clear_firmware_cache(paths: &firmware::CachePaths) -> Result<(), String> {
    match fs::remove_dir_all(&paths.update) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("could not clear {}: {e}", paths.update.display())),
    }
}

/// Upstream joins `ROM_DIR` and the timestamp without a separator.
fn eeprom_backup_path(root: &Path, now: i64) -> String {
    format!(
        "{}{}.eeprom",
        root.join("eeprom").display(),
        format_local_time(now, "-", "_", "-")
    )
}

fn write_eeprom_backup(bytes: &[u8]) -> Result<String, String> {
    let root = rnodeconf_root()?;
    fs::create_dir_all(root.join("eeprom")).map_err(|e| e.to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;
    let path = eeprom_backup_path(&root, now);
    fs::write(&path, bytes).map_err(|e| e.to_string())?;
    Ok(path)
}
