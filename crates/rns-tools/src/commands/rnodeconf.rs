//! rnodeconf-rs - RNode configuration and firmware utility.
//!
//! Device probe, info, configuration summary, EEPROM dump and backup, firmware
//! hash readout and TNC/normal startup mode follow upstream `rnodeconf`.
//! Firmware installation, EEPROM wipe and bootstrap, signing and trust
//! enrollment, and Bluetooth, Wi-Fi, display and interference-avoidance
//! mutations are disabled in this build.

use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{CommandFactory, Parser};
use rns_interface::rnode;
use rns_tools::RS_RETICULUM_VERSION;

#[allow(dead_code)]
#[path = "rnodeconf/eeprom.rs"]
mod eeprom;
#[allow(dead_code)]
#[path = "rnodeconf/firmware.rs"]
mod firmware;
#[allow(dead_code)]
#[path = "rnodeconf/flash.rs"]
mod flash;
#[allow(dead_code)]
#[path = "rnodeconf/model.rs"]
mod model;
#[path = "rnodeconf/plan.rs"]
mod plan;
#[path = "rnodeconf/session.rs"]
mod session;
#[allow(dead_code)]
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
    let args = Args::parse();
    if args.version {
        out(format!(
            "rnodeconf-rs {RS_RETICULUM_VERSION} (rnodeconf {RNODECONF_VERSION})"
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
    if let Some(message) = plan::refusal_without_port(&args) {
        eprintln!("rnodeconf-rs: {message}");
        return ExitCode::from(2);
    }
    let Some(port_path) = args.port.clone() else {
        out("");
        let _ = Args::command().print_help();
        out("");
        out("");
        return ExitCode::SUCCESS;
    };
    if let Some(message) = plan::refusal_with_port(&args) {
        eprintln!("rnodeconf-rs: {message}");
        return ExitCode::from(2);
    }

    log(format!("Opening serial port {port_path}..."));
    let port = match rns_interface::serial::open_port(
        serialport::new(&port_path, 115200).timeout(Duration::from_millis(100)),
    ) {
        Ok(port) => port,
        Err(e) => {
            log("Could not open the specified serial port. The contained exception was:");
            log(e.to_string());
            return ExitCode::SUCCESS;
        }
    };
    let mut rnode = RNode::new(port, port_path);
    match run_device(&mut rnode, &args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("rnodeconf-rs: {e}");
            ExitCode::from(1)
        }
    }
}

/// Upstream `main()` from the device probe on, for the operations this build
/// supports. Errors are the cases where upstream raises an exception.
fn run_device(rnode: &mut RNode, args: &Args) -> Result<ExitCode, String> {
    if let Err(e) = rnode.device_probe() {
        log("Serial port opened, but RNode did not respond. Is a valid firmware installed?");
        out(e);
        return Ok(graceful_exit(rnode, 0));
    }
    if rnode.detected == Some(true) && (rnode.platform.is_none() || rnode.mcu.is_none()) {
        rnode.platform = Some(model::PLATFORM_AVR);
        rnode.mcu = Some(model::MCU_1284P);
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

    if args.info {
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

    // initRadio: frequency and bandwidth are escaped, the one-byte setters are not.
    rnode.send(rnode::CMD_FREQUENCY, &radio_word(frequency)?)?;
    rnode.send(rnode::CMD_BANDWIDTH, &radio_word(bandwidth)?)?;
    rnode.send_raw_byte(rnode::CMD_TXPOWER, radio_byte(tx_power)?)?;
    rnode.send_raw_byte(rnode::CMD_SF, radio_byte(spreading_factor)?)?;
    rnode.send_raw_byte(rnode::CMD_CR, radio_byte(coding_rate)?)?;
    rnode.send_raw_byte(rnode::CMD_RADIO_STATE, rnode::RADIO_STATE_ON)?;
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
