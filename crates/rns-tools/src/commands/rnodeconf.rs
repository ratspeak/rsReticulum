//! rnodeconf-rs - RNode configuration and firmware utility.
//!
//! The safe inspection/configuration paths are implemented first. Firmware
//! flashing, ROM bootstrap, and full signing-key management remain
//! hardware-gated work.

use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{CommandFactory, Parser};
use rns_interface::{
    kiss, rnode, rnode_admin,
    rnode_capabilities::{
        RNodeCapabilities, RNodeCapabilityParseError, RNodeKnownRadioCapabilities,
        RNodeRadioCapabilities, RNodeRadioFamily, parse_rnode_capabilities, rnode_product_name,
    },
};
use rns_tools::RS_RETICULUM_VERSION;

// rnodeconf support is staged: safe inspection/config modules are compiled now,
// while hardware-gated flashing/signing paths are wired in behind explicit CLI flows.
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
#[allow(dead_code)]
#[path = "rnodeconf/trust.rs"]
mod trust;

#[derive(Parser, Debug)]
#[command(
    name = "rnodeconf-rs",
    about = "RNode Configuration and firmware utility",
    disable_version_flag = true
)]
struct Args {
    #[arg(short = 'i', long)]
    info: bool,
    #[arg(short = 'a', long)]
    autoinstall: bool,
    #[arg(short = 'u', long)]
    update: bool,
    #[arg(short = 'U', long = "force-update")]
    force_update: bool,
    #[arg(long = "fw-version")]
    fw_version: Option<String>,
    #[arg(long = "fw-url")]
    fw_url: Option<String>,
    #[arg(long)]
    nocheck: bool,
    #[arg(short = 'e', long)]
    extract: bool,
    #[arg(short = 'E', long = "use-extracted")]
    use_extracted: bool,
    #[arg(short = 'C', long = "clear-cache")]
    clear_cache: bool,
    #[arg(long = "baud-flash", default_value = "921600")]
    baud_flash: String,

    #[arg(short = 'N', long)]
    normal: bool,
    #[arg(short = 'T', long)]
    tnc: bool,

    #[arg(short = 'b', long = "bluetooth-on")]
    bluetooth_on: bool,
    #[arg(short = 'B', long = "bluetooth-off")]
    bluetooth_off: bool,
    #[arg(short = 'p', long = "bluetooth-pair")]
    bluetooth_pair: bool,

    #[arg(short = 'w', long = "wifi")]
    wifi: Option<String>,
    #[arg(long)]
    channel: Option<u8>,
    #[arg(long)]
    ssid: Option<String>,
    #[arg(long)]
    psk: Option<String>,
    #[arg(long = "show-psk")]
    show_psk: bool,
    #[arg(long)]
    ip: Option<String>,
    #[arg(long)]
    nm: Option<String>,

    #[arg(short = 'D', long = "display")]
    display: Option<i32>,
    #[arg(short = 't', long = "timeout")]
    timeout: Option<i32>,
    #[arg(short = 'R', long = "rotation")]
    rotation: Option<i32>,
    #[arg(long = "display-addr")]
    display_addr: Option<String>,
    #[arg(long = "recondition-display")]
    recondition_display: bool,
    #[arg(long = "np")]
    neopixel: Option<i32>,

    #[arg(long = "freq")]
    freq: Option<u32>,
    #[arg(long = "bw")]
    bandwidth: Option<u32>,
    #[arg(long = "txp")]
    tx_power: Option<u8>,
    #[arg(long = "sf")]
    spreading_factor: Option<u8>,
    #[arg(long = "cr")]
    coding_rate: Option<u8>,

    #[arg(short = 'x', long = "ia-enable")]
    ia_enable: bool,
    #[arg(short = 'X', long = "ia-disable")]
    ia_disable: bool,

    #[arg(short = 'c', long = "config")]
    config: bool,
    #[arg(long = "eeprom-backup")]
    eeprom_backup: bool,
    #[arg(long = "eeprom-dump")]
    eeprom_dump: bool,
    #[arg(long = "eeprom-wipe")]
    eeprom_wipe: bool,

    #[arg(short = 'P', long = "public")]
    public: bool,
    #[arg(long = "trust-key")]
    trust_key: Option<String>,

    #[arg(long)]
    version: bool,
    #[arg(short = 'f', long)]
    flash: bool,
    #[arg(short = 'r', long)]
    rom: bool,
    #[arg(short = 'k', long)]
    key: bool,
    #[arg(short = 'S', long)]
    sign: bool,
    #[arg(short = 'H', long = "firmware-hash")]
    firmware_hash: Option<String>,
    #[arg(short = 'K', long = "get-target-firmware-hash", hide = true)]
    get_target_firmware_hash: bool,
    #[arg(short = 'L', long = "get-firmware-hash", hide = true)]
    get_firmware_hash: bool,
    #[arg(long)]
    platform: Option<String>,
    #[arg(long)]
    product: Option<String>,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    hwrev: Option<u8>,

    /// Serial port where RNode is attached.
    port: Option<PathBuf>,
}

pub(crate) fn main() -> ExitCode {
    let args = Args::parse();
    if args.version {
        println!("rnodeconf-rs {RS_RETICULUM_VERSION}");
        return ExitCode::SUCCESS;
    }
    if let Some(trust_key) = args.trust_key.as_deref() {
        let paths = match rnodeconf_cache_paths() {
            Ok(paths) => paths,
            Err(e) => {
                eprintln!("rnodeconf-rs: {e}");
                return ExitCode::from(2);
            }
        };
        match store_trusted_key(trust_key, &paths) {
            Ok(path) => {
                println!("Trusted key written to: {}", path.display());
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("rnodeconf-rs: {e}");
                return ExitCode::from(2);
            }
        }
    }
    if args.key || args.sign || args.public {
        eprintln!("rnodeconf-rs: signing key management is not fully implemented yet");
        return ExitCode::from(2);
    }
    if args.flash || args.rom || args.autoinstall || args.update || args.force_update {
        eprintln!("rnodeconf-rs: firmware flashing is not implemented yet");
        return ExitCode::from(2);
    }
    if args.extract
        || args.use_extracted
        || args.fw_version.is_some()
        || args.fw_url.is_some()
        || args.nocheck
        || args.platform.is_some()
        || args.product.is_some()
        || args.model.is_some()
        || args.hwrev.is_some()
        || args.baud_flash != "921600"
    {
        eprintln!(
            "rnodeconf-rs: firmware planning/cache options are not implemented yet; flashing and update flows remain disabled"
        );
        return ExitCode::from(2);
    }
    if args.eeprom_wipe {
        eprintln!(
            "rnodeconf-rs: --eeprom-wipe is destructive and is disabled until the full provisioning flow is implemented"
        );
        return ExitCode::from(2);
    }
    if let Some(hash) = args.firmware_hash.as_deref() {
        if let Err(e) = firmware::parse_sha256_hex(hash) {
            eprintln!("rnodeconf-rs: {e}");
            return ExitCode::from(2);
        }
        eprintln!(
            "rnodeconf-rs: --firmware-hash writes device trust state and is disabled until signing/provisioning is implemented"
        );
        return ExitCode::from(2);
    }
    if args.clear_cache {
        let paths = match rnodeconf_cache_paths() {
            Ok(paths) => paths,
            Err(e) => {
                eprintln!("rnodeconf-rs: {e}");
                return ExitCode::from(2);
            }
        };
        if let Err(e) = clear_firmware_cache(&paths) {
            eprintln!("rnodeconf-rs: {e}");
            return ExitCode::from(1);
        }
        println!("Firmware cache cleared.");
        return ExitCode::SUCCESS;
    }

    let actions = match build_actions(&args) {
        Ok(actions) => actions,
        Err(e) => {
            eprintln!("rnodeconf-rs: {e}");
            return ExitCode::from(2);
        }
    };
    if actions.is_empty() {
        let mut cmd = Args::command();
        let _ = cmd.print_help();
        println!();
        return ExitCode::SUCCESS;
    }

    let cache_paths = if args.eeprom_backup {
        match rnodeconf_cache_paths() {
            Ok(paths) => Some(paths),
            Err(e) => {
                eprintln!("rnodeconf-rs: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };

    let Some(port_path) = args.port.as_ref() else {
        eprintln!("rnodeconf-rs: serial port is required for device operations");
        return ExitCode::from(2);
    };

    let mut port = match serialport::new(port_path.to_string_lossy(), 115200)
        .timeout(Duration::from_millis(250))
        .open()
    {
        Ok(port) => port,
        Err(e) => {
            eprintln!("rnodeconf-rs: could not open {}: {e}", port_path.display());
            return ExitCode::from(1);
        }
    };

    for frame in actions {
        let raw = rnode_admin::encode_frame(frame.command, &frame.payload);
        if let Err(e) = port.write_all(&raw).and_then(|_| port.flush()) {
            eprintln!("rnodeconf-rs: serial write failed: {e}");
            return ExitCode::from(1);
        }
    }

    let responses = read_responses(&mut *port, Duration::from_millis(750));
    if let Err(e) = print_responses(&responses, &args, cache_paths.as_ref()) {
        eprintln!("rnodeconf-rs: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn build_actions(args: &Args) -> Result<Vec<rnode_admin::AdminFrame>, String> {
    let mut actions = Vec::new();

    if args.info {
        actions.extend(rnode_admin::detect_sequence());
        actions.push(rnode_admin::eeprom_read_frame());
    }
    if args.normal {
        actions.push(frame(rnode::CMD_CONF_DELETE, &[0]));
    }
    if args.tnc {
        actions.push(frame(rnode::CMD_CONF_SAVE, &[0]));
    }
    if args.bluetooth_on {
        actions.push(frame(rnode::CMD_BT_CTRL, &[1]));
    }
    if args.bluetooth_off {
        actions.push(frame(rnode::CMD_BT_CTRL, &[0]));
    }
    if args.bluetooth_pair {
        actions.push(frame(rnode::CMD_BT_CTRL, &[2]));
    }

    if let Some(mode) = args.wifi.as_deref() {
        let mode = match mode.to_ascii_lowercase().as_str() {
            "off" | "none" => rnode_admin::WifiMode::Off,
            "station" | "sta" => rnode_admin::WifiMode::Station,
            "ap" | "accesspoint" | "access_point" => rnode_admin::WifiMode::AccessPoint,
            _ => return Err("WiFi mode must be OFF, AP or STATION".to_string()),
        };
        actions.push(frame(rnode::CMD_WIFI_MODE, &mode.payload()));
    }
    if let Some(channel) = args.channel {
        actions.push(frame(rnode::CMD_WIFI_CHN, &[channel]));
    }
    if let Some(ssid) = args.ssid.as_deref() {
        actions.push(frame(
            rnode::CMD_WIFI_SSID,
            &rnode_admin::nullable_string_payload(non_none_value(ssid)),
        ));
    }
    if let Some(psk) = args.psk.as_deref() {
        actions.push(frame(
            rnode::CMD_WIFI_PSK,
            &rnode_admin::nullable_string_payload(non_none_value(psk)),
        ));
    }
    if args.show_psk {
        actions.push(frame(rnode::CMD_WIFI_PSK, &[0xFF]));
    }
    if let Some(ip) = args.ip.as_deref() {
        let payload = optional_ipv4_payload(ip)?;
        actions.push(frame(rnode::CMD_WIFI_IP, &payload));
    }
    if let Some(nm) = args.nm.as_deref() {
        let payload = optional_ipv4_payload(nm)?;
        actions.push(frame(rnode::CMD_WIFI_NM, &payload));
    }

    if let Some(intensity) = args.display {
        actions.push(frame(rnode::CMD_DISP_INT, &[clamp_u8(intensity, 255)]));
    }
    if let Some(timeout) = args.timeout {
        actions.push(frame(rnode::CMD_DISP_BLNK, &[clamp_u8(timeout, 255)]));
    }
    if let Some(rotation) = args.rotation {
        actions.push(frame(rnode::CMD_DISP_ROT, &[clamp_u8(rotation, 3)]));
    }
    if let Some(addr) = args.display_addr.as_deref() {
        let addr = u8::from_str_radix(addr.trim_start_matches("0x"), 16)
            .map_err(|e| format!("invalid display address: {e}"))?;
        actions.push(frame(rnode::CMD_DISP_ADR, &[addr]));
    }
    if args.recondition_display {
        actions.push(frame(rnode::CMD_DISP_RCND, &[1]));
    }
    if let Some(intensity) = args.neopixel {
        actions.push(frame(rnode::CMD_NP_INT, &[clamp_u8(intensity, 255)]));
    }

    if let Some(freq) = args.freq {
        actions.push(frame(rnode::CMD_FREQUENCY, &freq.to_be_bytes()));
    }
    if let Some(bw) = args.bandwidth {
        actions.push(frame(rnode::CMD_BANDWIDTH, &bw.to_be_bytes()));
    }
    if let Some(txp) = args.tx_power {
        actions.push(frame(rnode::CMD_TXPOWER, &[txp]));
    }
    if let Some(sf) = args.spreading_factor {
        actions.push(frame(rnode::CMD_SF, &[sf]));
    }
    if let Some(cr) = args.coding_rate {
        actions.push(frame(rnode::CMD_CR, &[cr]));
    }
    if args.ia_enable {
        actions.push(frame(rnode::CMD_DIS_IA, &[0]));
    }
    if args.ia_disable {
        actions.push(frame(rnode::CMD_DIS_IA, &[1]));
    }

    if args.config {
        actions.push(frame(rnode::CMD_CFG_READ, &[0]));
    }
    if args.eeprom_dump || args.eeprom_backup {
        actions.push(rnode_admin::eeprom_read_frame());
    }
    if args.eeprom_wipe {
        actions.push(rnode_admin::eeprom_wipe_frame());
    }
    if let Some(hash) = args.firmware_hash.as_deref() {
        let hash = firmware::parse_sha256_hex(hash)?;
        actions.push(trust::firmware_hash_frame(&hash));
    }
    if args.get_target_firmware_hash {
        actions.push(frame(rnode::CMD_HASHES, &[1]));
    }
    if args.get_firmware_hash {
        actions.push(frame(rnode::CMD_HASHES, &[2]));
    }

    Ok(actions)
}

fn frame(command: u8, payload: &[u8]) -> rnode_admin::AdminFrame {
    rnode_admin::AdminFrame {
        command,
        payload: payload.to_vec(),
    }
}

fn non_none_value(value: &str) -> Option<&str> {
    (!value.eq_ignore_ascii_case("none")).then_some(value)
}

fn optional_ipv4_payload(value: &str) -> Result<Vec<u8>, String> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(vec![0, 0, 0, 0]);
    }
    let addr: Ipv4Addr = value
        .parse()
        .map_err(|e| format!("invalid IPv4 address {value}: {e}"))?;
    Ok(rnode_admin::ipv4_payload(addr).to_vec())
}

fn clamp_u8(value: i32, max: u8) -> u8 {
    value.clamp(0, i32::from(max)) as u8
}

fn read_responses(
    port: &mut dyn serialport::SerialPort,
    total_timeout: Duration,
) -> Vec<rnode_admin::AdminFrame> {
    let mut frames = Vec::new();
    let mut deframer = kiss::RawKissDeframer::new();
    let mut buf = [0u8; 512];
    let deadline = Instant::now() + total_timeout;
    while Instant::now() < deadline {
        match port.read(&mut buf) {
            Ok(n) if n > 0 => frames.extend(
                deframer
                    .feed(&buf[..n])
                    .into_iter()
                    .map(|(command, payload)| rnode_admin::AdminFrame { command, payload }),
            ),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    frames
}

fn print_responses(
    frames: &[rnode_admin::AdminFrame],
    args: &Args,
    cache_paths: Option<&firmware::CachePaths>,
) -> Result<(), String> {
    for frame in frames {
        match frame.command {
            rnode::CMD_BT_PIN => {
                if let Some(pin) = rnode_admin::parse_bt_pin(frame) {
                    println!("Bluetooth pairing PIN: {pin:06}");
                }
            }
            rnode::CMD_FW_VERSION if frame.payload.len() >= 2 => {
                println!(
                    "Firmware version: {}.{}",
                    frame.payload[0], frame.payload[1]
                );
            }
            rnode::CMD_PLATFORM => println!("Platform: {}", hex::encode(&frame.payload)),
            rnode::CMD_MCU => println!("MCU: {}", hex::encode(&frame.payload)),
            rnode::CMD_BOARD => println!("Board: {}", hex::encode(&frame.payload)),
            rnode::CMD_DEV_HASH => println!("Device hash: {}", hex::encode(&frame.payload)),
            rnode::CMD_HASHES => println!("Firmware hash: {}", hex::encode(&frame.payload)),
            rnode::CMD_CFG_READ => {
                println!("Config sector: {}", hex::encode(&frame.payload));
            }
            rnode::CMD_ROM_READ => {
                if args.eeprom_dump {
                    println!("EEPROM contents: {}", hex::encode(&frame.payload));
                }
                match eeprom::EepromImage::new(frame.payload.clone()) {
                    Ok(image) => {
                        for line in eeprom_summary_lines(&image) {
                            println!("{line}");
                        }
                    }
                    Err(e) => println!("EEPROM: {e}"),
                }
                if args.eeprom_backup {
                    let Some(paths) = cache_paths else {
                        return Err("EEPROM backup requested without cache paths".to_string());
                    };
                    let path = write_eeprom_backup(paths, &frame.payload)?;
                    println!("EEPROM backup written to: {}", path.display());
                }
            }
            _ => println!("0x{:02x}: {}", frame.command, hex::encode(&frame.payload)),
        }
    }
    Ok(())
}

fn eeprom_summary_lines(image: &eeprom::EepromImage) -> Vec<String> {
    let identity = image.identity();
    let capabilities = match parse_rnode_capabilities(image.bytes()) {
        Ok(capabilities) => capabilities,
        Err(RNodeCapabilityParseError::InfoNotLocked) => {
            return vec!["EEPROM: not provisioned or info lock missing".to_string()];
        }
        Err(error) => {
            let mut lines = private_eeprom_identity_lines(&identity, false);
            lines.push(format!("  Radio capabilities: unavailable ({error})"));
            append_startup_config_lines(image, &mut lines);
            return lines;
        }
    };

    let mut lines = private_eeprom_identity_lines(&identity, true);
    append_capability_lines(capabilities, &mut lines);
    append_startup_config_lines(image, &mut lines);
    lines
}

fn private_eeprom_identity_lines(
    identity: &eeprom::IdentityInfo,
    identity_validated: bool,
) -> Vec<String> {
    let checksum_status = if identity_validated {
        "valid"
    } else {
        "invalid"
    };
    let product = if identity_validated {
        format!("  Product code: 0x{:02x}", identity.product)
    } else {
        format!("  Product code: 0x{:02x} (unvalidated)", identity.product)
    };
    let model = if identity_validated {
        format!("  Model: 0x{:02x}", identity.model)
    } else {
        format!("  Model code: 0x{:02x} (unvalidated)", identity.model)
    };

    vec![
        "EEPROM: provisioned".to_string(),
        product,
        model,
        format!("  Hardware revision: {}", identity.hw_rev),
        format!("  Serial: {}", hex::encode(identity.serial.to_be_bytes())),
        format!("  Manufactured: {}", identity.made),
        format!("  Identity checksum: {checksum_status}"),
    ]
}

fn append_capability_lines(capabilities: RNodeCapabilities, lines: &mut Vec<String>) {
    let product = rnode_product_name(capabilities.product_code()).unwrap_or("Unknown product");
    lines[1] = format!(
        "  Product: {product} (0x{:02x})",
        capabilities.product_code()
    );
    lines[2] = format!("  Model: 0x{:02x}", capabilities.model_code());

    match capabilities.radio() {
        RNodeRadioCapabilities::Known(radio) => append_known_radio_lines(radio, lines),
        _ => {
            lines.push("  Radio capabilities: unavailable for this model".to_string());
        }
    }
}

fn append_known_radio_lines(radio: RNodeKnownRadioCapabilities, lines: &mut Vec<String>) {
    lines.extend([
        format!("  Radio family: {}", radio_family_name(radio.family())),
        format!(
            "  Frequency range: {} - {} Hz",
            radio.min_frequency_hz(),
            radio.max_frequency_hz()
        ),
        format!("  Maximum TX power: {} dBm", radio.max_tx_power_dbm()),
    ]);
}

fn radio_family_name(family: RNodeRadioFamily) -> &'static str {
    match family {
        RNodeRadioFamily::Sx1262 => "SX1262",
        RNodeRadioFamily::Sx1268 => "SX1268",
        RNodeRadioFamily::Sx1276 => "SX1276",
        RNodeRadioFamily::Sx1278 => "SX1278",
        RNodeRadioFamily::Sx1280 => "SX1280",
        RNodeRadioFamily::Sx1262AndSx1280 => "SX1262 + SX1280",
        _ => "Unrecognized",
    }
}

fn append_startup_config_lines(image: &eeprom::EepromImage, lines: &mut Vec<String>) {
    if let Some(radio) = image.radio_config() {
        let bitrate =
            rnode::calculate_bitrate(radio.spreading_factor, radio.coding_rate, radio.bandwidth);
        lines.extend([
            "  Startup mode: TNC".to_string(),
            format!("    Frequency: {} Hz", radio.frequency),
            format!("    Bandwidth: {} Hz", radio.bandwidth),
            format!("    TX power: {} dBm", radio.tx_power),
            format!("    Spreading factor: {}", radio.spreading_factor),
            format!("    Coding rate: {}", radio.coding_rate),
            format!("    On-air bitrate: {bitrate} bps"),
        ]);
    } else {
        lines.push("  Startup mode: Normal (host-controlled)".to_string());
    }
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

fn store_trusted_key(trust_key_hex: &str, paths: &firmware::CachePaths) -> Result<PathBuf, String> {
    let public_key =
        hex::decode(trust_key_hex).map_err(|e| format!("invalid trust key hex: {e}"))?;
    if public_key.is_empty() {
        return Err("trusted public key cannot be empty".to_string());
    }
    trust::write_trusted_key(&paths.root, &public_key)
        .map_err(|e| format!("could not write trusted key: {e}"))
}

fn clear_firmware_cache(paths: &firmware::CachePaths) -> Result<(), String> {
    for dir in [&paths.update, &paths.extracted] {
        match fs::remove_dir_all(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("could not clear {}: {e}", dir.display())),
        }
        fs::create_dir_all(dir)
            .map_err(|e| format!("could not recreate {}: {e}", dir.display()))?;
    }
    Ok(())
}

fn write_eeprom_backup(paths: &firmware::CachePaths, bytes: &[u8]) -> Result<PathBuf, String> {
    fs::create_dir_all(&paths.eeprom)
        .map_err(|e| format!("could not create {}: {e}", paths.eeprom.display()))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock before Unix epoch: {e}"))?
        .as_secs();
    let path = paths.eeprom.join(format!("{timestamp}.eeprom"));
    fs::write(&path, bytes).map_err(|e| format!("could not write {}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeRNode {
        eeprom: Vec<u8>,
        config_dump: Vec<u8>,
        device_hash: [u8; 32],
        target_firmware_hash: [u8; 32],
        firmware_hash: [u8; 32],
        accepted_firmware_hash: Option<[u8; 32]>,
        accepted_device_signature: Option<[u8; 64]>,
    }

    impl FakeRNode {
        fn new() -> Self {
            Self {
                eeprom: (0..eeprom::EEPROM_SIZE).map(|i| i as u8).collect(),
                config_dump: vec![0x73, 0x01, 0x02, 0x03],
                device_hash: [0xA5; 32],
                target_firmware_hash: [0x11; 32],
                firmware_hash: [0x22; 32],
                accepted_firmware_hash: None,
                accepted_device_signature: None,
            }
        }

        fn transact(
            &mut self,
            raw: &[u8],
        ) -> (Vec<rnode_admin::AdminFrame>, Vec<rnode_admin::AdminFrame>) {
            let requests = rnode_admin::decode_frames(raw);
            let responses = requests
                .iter()
                .filter_map(|request| self.apply(request))
                .collect();
            (requests, responses)
        }

        fn apply(&mut self, request: &rnode_admin::AdminFrame) -> Option<rnode_admin::AdminFrame> {
            match request.command {
                rnode::CMD_DETECT if request.payload == [rnode::DETECT_REQ] => {
                    Some(frame(rnode::CMD_DETECT, &[rnode::DETECT_RESP]))
                }
                rnode::CMD_FW_VERSION => Some(frame(rnode::CMD_FW_VERSION, &[1, 74])),
                rnode::CMD_PLATFORM => Some(frame(rnode::CMD_PLATFORM, &[model::PLATFORM_ESP32])),
                rnode::CMD_MCU => Some(frame(rnode::CMD_MCU, &[model::MCU_ESP32])),
                rnode::CMD_BOARD => Some(frame(rnode::CMD_BOARD, &[0x01])),
                rnode::CMD_DEV_HASH => Some(frame(rnode::CMD_DEV_HASH, &self.device_hash)),
                rnode::CMD_HASHES => match request.payload.first().copied() {
                    Some(1) => Some(frame(rnode::CMD_HASHES, &self.target_firmware_hash)),
                    Some(2) => Some(frame(rnode::CMD_HASHES, &self.firmware_hash)),
                    _ => Some(frame(rnode::CMD_HASHES, &[0x00])),
                },
                rnode::CMD_CFG_READ => Some(frame(rnode::CMD_CFG_READ, &self.config_dump)),
                rnode::CMD_ROM_READ => Some(frame(rnode::CMD_ROM_READ, &self.eeprom)),
                rnode::CMD_ROM_WRITE if request.payload.len() == 2 => {
                    let address = request.payload[0] as usize;
                    if let Some(cell) = self.eeprom.get_mut(address) {
                        *cell = request.payload[1];
                    }
                    Some(frame(rnode::CMD_ROM_WRITE, &request.payload))
                }
                rnode::CMD_ROM_WIPE => {
                    self.eeprom.fill(0xFF);
                    Some(frame(rnode::CMD_ROM_WIPE, &[0xF8]))
                }
                rnode::CMD_BT_CTRL if request.payload == [2] => {
                    Some(frame(rnode::CMD_BT_PIN, &123456u32.to_be_bytes()))
                }
                rnode::CMD_FW_HASH if request.payload.len() == 32 => {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&request.payload);
                    self.accepted_firmware_hash = Some(hash);
                    Some(frame(rnode::CMD_FW_HASH, &request.payload))
                }
                rnode::CMD_DEV_SIG if request.payload.len() == 64 => {
                    let mut signature = [0u8; 64];
                    signature.copy_from_slice(&request.payload);
                    self.accepted_device_signature = Some(signature);
                    Some(frame(rnode::CMD_DEV_SIG, &request.payload))
                }
                _ => Some(frame(request.command, &request.payload)),
            }
        }
    }

    fn commands(args: &[&str]) -> Vec<u8> {
        let args = Args::parse_from(std::iter::once("rnodeconf").chain(args.iter().copied()));
        build_actions(&args)
            .unwrap()
            .into_iter()
            .map(|f| f.command)
            .collect()
    }

    fn actions(args: &[&str]) -> Vec<rnode_admin::AdminFrame> {
        let args = Args::parse_from(std::iter::once("rnodeconf").chain(args.iter().copied()));
        build_actions(&args).unwrap()
    }

    fn encode_actions(actions: &[rnode_admin::AdminFrame]) -> Vec<u8> {
        let mut raw = Vec::new();
        for action in actions {
            raw.extend_from_slice(&rnode_admin::encode_frame(action.command, &action.payload));
        }
        raw
    }

    fn assert_has_frame(frames: &[rnode_admin::AdminFrame], command: u8, payload: &[u8]) {
        assert!(
            frames
                .iter()
                .any(|frame| frame.command == command && frame.payload == payload),
            "missing command 0x{command:02x} with payload {} in {frames:?}",
            hex::encode(payload)
        );
    }

    fn provisioned_eeprom(model: u8, radio: Option<&eeprom::RadioConfig>) -> eeprom::EepromImage {
        let identity = eeprom::IdentityInfo {
            product: model::PRODUCT_RNODE,
            model,
            hw_rev: 2,
            serial: 0x01020304,
            made: 0x6553F100,
        };
        let mut bytes = vec![0xFF; eeprom::EEPROM_SIZE];
        let mut writes = eeprom::identity_write_frames(&identity);
        if let Some(radio) = radio {
            writes.extend(eeprom::radio_config_write_frames(radio));
        }
        for frame in writes {
            let address = frame.payload[0] as usize;
            bytes[address] = frame.payload[1];
        }
        eeprom::EepromImage::new(bytes).unwrap()
    }

    #[test]
    fn info_sequence_matches_upstream_probe_order() {
        assert_eq!(
            commands(&["--info", "fake"]),
            vec![
                rnode::CMD_DETECT,
                rnode::CMD_FW_VERSION,
                rnode::CMD_PLATFORM,
                rnode::CMD_MCU,
                rnode::CMD_BOARD,
                rnode::CMD_DEV_HASH,
                rnode::CMD_HASHES,
                rnode::CMD_HASHES,
                rnode::CMD_ROM_READ,
            ]
        );
    }

    #[test]
    fn wifi_and_bluetooth_actions_use_extended_commands() {
        let args = Args::parse_from([
            "rnodeconf",
            "--bluetooth-pair",
            "--wifi",
            "AP",
            "--ssid",
            "RNode",
            "--psk",
            "secret",
            "--ip",
            "192.168.1.10",
            "--nm",
            "255.255.255.0",
            "fake",
        ]);
        let frames = build_actions(&args).unwrap();
        assert_eq!(frames[0].command, rnode::CMD_BT_CTRL);
        assert_eq!(frames[0].payload, vec![2]);
        assert!(frames.iter().any(|f| f.command == rnode::CMD_WIFI_IP));
        assert!(frames.iter().any(|f| f.command == rnode::CMD_WIFI_NM));
    }

    #[test]
    fn info_sequence_round_trips_against_fake_rnode() {
        let actions = actions(&["--info", "fake"]);
        let mut fake = FakeRNode::new();
        let (requests, responses) = fake.transact(&encode_actions(&actions));

        assert_eq!(requests, actions);
        assert_eq!(
            responses
                .iter()
                .map(|frame| frame.command)
                .collect::<Vec<_>>(),
            vec![
                rnode::CMD_DETECT,
                rnode::CMD_FW_VERSION,
                rnode::CMD_PLATFORM,
                rnode::CMD_MCU,
                rnode::CMD_BOARD,
                rnode::CMD_DEV_HASH,
                rnode::CMD_HASHES,
                rnode::CMD_HASHES,
                rnode::CMD_ROM_READ,
            ]
        );
        assert_has_frame(&responses, rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
        assert_has_frame(&responses, rnode::CMD_FW_VERSION, &[1, 74]);
        assert_has_frame(&responses, rnode::CMD_PLATFORM, &[model::PLATFORM_ESP32]);
        assert_has_frame(&responses, rnode::CMD_MCU, &[model::MCU_ESP32]);
        assert_has_frame(&responses, rnode::CMD_ROM_READ, &FakeRNode::new().eeprom);
    }

    #[test]
    fn config_dump_and_eeprom_read_wipe_round_trip_against_fake_rnode() {
        let actions = actions(&["--config", "--eeprom-dump", "--eeprom-wipe", "fake"]);
        let original_eeprom = FakeRNode::new().eeprom;
        let mut fake = FakeRNode::new();
        let (requests, responses) = fake.transact(&encode_actions(&actions));

        assert_eq!(
            requests
                .iter()
                .map(|frame| frame.command)
                .collect::<Vec<_>>(),
            vec![
                rnode::CMD_CFG_READ,
                rnode::CMD_ROM_READ,
                rnode::CMD_ROM_WIPE
            ]
        );
        assert_has_frame(&responses, rnode::CMD_CFG_READ, &[0x73, 0x01, 0x02, 0x03]);
        assert_has_frame(&responses, rnode::CMD_ROM_READ, &original_eeprom);
        assert_has_frame(&responses, rnode::CMD_ROM_WIPE, &[0xF8]);
        assert!(fake.eeprom.iter().all(|byte| *byte == 0xFF));
    }

    #[test]
    fn eeprom_write_frames_mutate_fake_rnode_memory() {
        let info = eeprom::IdentityInfo {
            product: model::PRODUCT_RNODE,
            model: model::MODEL_B4_TCXO,
            hw_rev: 3,
            serial: 0x01020304,
            made: 0x6553F100,
        };
        let mut writes = eeprom::identity_write_frames(&info);
        writes.extend(eeprom::radio_config_write_frames(&eeprom::RadioConfig {
            spreading_factor: 7,
            coding_rate: 5,
            tx_power: 14,
            bandwidth: 125000,
            frequency: 868000000,
        }));

        let mut fake = FakeRNode::new();
        let (requests, responses) = fake.transact(&encode_actions(&writes));

        assert_eq!(requests, writes);
        assert_eq!(responses.len(), writes.len());
        assert_eq!(fake.eeprom[eeprom::ADDR_PRODUCT], model::PRODUCT_RNODE);
        assert_eq!(fake.eeprom[eeprom::ADDR_MODEL], 0xB4);
        assert_eq!(fake.eeprom[eeprom::ADDR_HW_REV], 3);
        assert_eq!(
            &fake.eeprom[eeprom::ADDR_SERIAL..eeprom::ADDR_SERIAL + 4],
            &0x01020304u32.to_be_bytes()
        );
        assert_eq!(fake.eeprom[eeprom::ADDR_INFO_LOCK], eeprom::INFO_LOCK_BYTE);
        assert_eq!(fake.eeprom[eeprom::ADDR_CONF_SF], 7);
        assert_eq!(
            &fake.eeprom[eeprom::ADDR_CONF_FREQ..eeprom::ADDR_CONF_FREQ + 4],
            &868000000u32.to_be_bytes()
        );
        assert_eq!(fake.eeprom[eeprom::ADDR_CONF_OK], eeprom::CONF_OK_BYTE);
    }

    #[test]
    fn device_control_actions_emit_expected_admin_frames() {
        let frames = actions(&[
            "--bluetooth-on",
            "--bluetooth-pair",
            "--wifi",
            "AP",
            "--channel",
            "6",
            "--ssid",
            "RNode",
            "--psk",
            "none",
            "--show-psk",
            "--ip",
            "none",
            "--nm",
            "255.255.255.0",
            "--display",
            "192",
            "--timeout",
            "30",
            "--rotation",
            "2",
            "--display-addr",
            "0x3c",
            "--recondition-display",
            "--np",
            "16",
            "--freq",
            "868000000",
            "--bw",
            "125000",
            "--txp",
            "14",
            "--sf",
            "7",
            "--cr",
            "5",
            "--ia-enable",
            "--ia-disable",
            "fake",
        ]);

        assert_has_frame(&frames, rnode::CMD_BT_CTRL, &[1]);
        assert_has_frame(&frames, rnode::CMD_BT_CTRL, &[2]);
        assert_has_frame(
            &frames,
            rnode::CMD_WIFI_MODE,
            &[rnode_admin::WifiMode::AccessPoint as u8],
        );
        assert_has_frame(&frames, rnode::CMD_WIFI_CHN, &[6]);
        assert_has_frame(&frames, rnode::CMD_WIFI_SSID, b"RNode\0");
        assert_has_frame(&frames, rnode::CMD_WIFI_PSK, &[0]);
        assert_has_frame(&frames, rnode::CMD_WIFI_PSK, &[0xFF]);
        assert_has_frame(&frames, rnode::CMD_WIFI_IP, &[0, 0, 0, 0]);
        assert_has_frame(&frames, rnode::CMD_WIFI_NM, &[255, 255, 255, 0]);
        assert_has_frame(&frames, rnode::CMD_DISP_INT, &[192]);
        assert_has_frame(&frames, rnode::CMD_DISP_BLNK, &[30]);
        assert_has_frame(&frames, rnode::CMD_DISP_ROT, &[2]);
        assert_has_frame(&frames, rnode::CMD_DISP_ADR, &[0x3C]);
        assert_has_frame(&frames, rnode::CMD_DISP_RCND, &[1]);
        assert_has_frame(&frames, rnode::CMD_NP_INT, &[16]);
        assert_has_frame(&frames, rnode::CMD_FREQUENCY, &868000000u32.to_be_bytes());
        assert_has_frame(&frames, rnode::CMD_BANDWIDTH, &125000u32.to_be_bytes());
        assert_has_frame(&frames, rnode::CMD_TXPOWER, &[14]);
        assert_has_frame(&frames, rnode::CMD_SF, &[7]);
        assert_has_frame(&frames, rnode::CMD_CR, &[5]);
        assert_has_frame(&frames, rnode::CMD_DIS_IA, &[0]);
        assert_has_frame(&frames, rnode::CMD_DIS_IA, &[1]);

        let mut fake = FakeRNode::new();
        let (_, responses) = fake.transact(&encode_actions(&frames));
        assert_has_frame(&responses, rnode::CMD_BT_PIN, &123456u32.to_be_bytes());
    }

    #[test]
    fn firmware_hash_and_device_signature_frames_round_trip_against_fake_rnode() {
        let hash = [0xAB; 32];
        let signature = [0xCD; 64];
        let hash_hex = hex::encode(hash);
        let mut frames = actions(&["--firmware-hash", &hash_hex, "fake"]);
        frames.push(trust::device_signature_frame(&signature));

        let mut fake = FakeRNode::new();
        let (requests, responses) = fake.transact(&encode_actions(&frames));

        assert_eq!(requests, frames);
        assert_eq!(fake.accepted_firmware_hash, Some(hash));
        assert_eq!(fake.accepted_device_signature, Some(signature));
        assert_has_frame(&responses, rnode::CMD_FW_HASH, &hash);
        assert_has_frame(&responses, rnode::CMD_DEV_SIG, &signature);
    }

    #[test]
    fn display_and_neopixel_values_clamp_like_upstream_cli() {
        let frames = actions(&[
            "--display=-5",
            "--timeout",
            "300",
            "--rotation",
            "8",
            "--np",
            "512",
            "fake",
        ]);

        assert_has_frame(&frames, rnode::CMD_DISP_INT, &[0]);
        assert_has_frame(&frames, rnode::CMD_DISP_BLNK, &[255]);
        assert_has_frame(&frames, rnode::CMD_DISP_ROT, &[3]);
        assert_has_frame(&frames, rnode::CMD_NP_INT, &[255]);
    }

    #[test]
    fn eeprom_summary_reports_validated_identity_capabilities_and_radio_config() {
        let radio = eeprom::RadioConfig {
            spreading_factor: 7,
            coding_rate: 5,
            tx_power: 14,
            bandwidth: 125000,
            frequency: 868000000,
        };
        let image = provisioned_eeprom(0xB4, Some(&radio));
        let lines = eeprom_summary_lines(&image);

        assert!(lines.iter().any(|line| line == "EEPROM: provisioned"));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Product: RNode (0x03)"))
        );
        assert!(lines.iter().any(|line| line == "  Model: 0xb4"));
        assert!(lines.iter().any(|line| line == "  Radio family: SX1278"));
        assert!(
            lines
                .iter()
                .any(|line| line == "  Frequency range: 420000000 - 520000000 Hz")
        );
        assert!(
            lines
                .iter()
                .any(|line| line == "  Maximum TX power: 17 dBm")
        );
        assert!(lines.iter().any(|line| line.contains("Startup mode: TNC")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Frequency: 868000000 Hz"))
        );
        assert!(!lines.iter().any(|line| line.contains("420 - 520 MHz")));
    }

    #[test]
    fn eeprom_summary_quarantines_ambiguous_model_capabilities() {
        let image = provisioned_eeprom(0x16, None);
        let lines = eeprom_summary_lines(&image);

        assert!(lines.iter().any(|line| line == "  Model: 0x16"));
        assert!(
            lines
                .iter()
                .any(|line| line == "  Radio capabilities: unavailable for this model")
        );
        assert!(!lines.iter().any(|line| line.contains("Radio family:")));
        assert!(!lines.iter().any(|line| line.contains("Frequency range:")));
        assert!(!lines.iter().any(|line| line.contains("Maximum TX power:")));
    }

    #[test]
    fn eeprom_summary_does_not_trust_an_invalid_identity_checksum() {
        let image = provisioned_eeprom(0xB4, None);
        let mut bytes = image.bytes().to_vec();
        bytes[eeprom::ADDR_CHKSUM] ^= 0x01;
        let invalid = eeprom::EepromImage::new(bytes).unwrap();
        let lines = eeprom_summary_lines(&invalid);

        assert!(
            lines
                .iter()
                .any(|line| line == "  Product code: 0x03 (unvalidated)")
        );
        assert!(
            lines
                .iter()
                .any(|line| line == "  Model code: 0xb4 (unvalidated)")
        );
        assert!(
            lines
                .iter()
                .any(|line| line == "  Identity checksum: invalid")
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Radio capabilities: unavailable"))
        );
        assert!(lines.iter().any(|line| line == "  Serial: 01020304"));
        assert!(!lines.iter().any(|line| line.contains("Product: RNode")));
        assert!(!lines.iter().any(|line| line.contains("Radio family:")));
        assert!(!lines.iter().any(|line| line.contains("Frequency range:")));
        assert!(!lines.iter().any(|line| line.contains("Maximum TX power:")));
    }

    #[test]
    fn trusted_key_storage_uses_upstream_directory_shape() {
        let root = std::env::temp_dir().join(format!(
            "rnodeconf-trust-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let paths = firmware::CachePaths::new(&root);
        let trusted = store_trusted_key("aabbcc", &paths).unwrap();
        assert_eq!(
            trusted,
            root.join("trusted_keys")
                .join(trust::trusted_key_filename(&[0xAA, 0xBB, 0xCC]))
        );
        assert_eq!(fs::read(&trusted).unwrap(), vec![0xAA, 0xBB, 0xCC]);
        let _ = fs::remove_dir_all(root);
    }
}
