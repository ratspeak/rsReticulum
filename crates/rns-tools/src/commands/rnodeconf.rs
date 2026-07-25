//! rnodeconf-rs - RNode configuration and firmware utility.
//!
//! The safe inspection/configuration paths are implemented first. Firmware
//! flashing, ROM bootstrap, and full signing-key management remain
//! hardware-gated work.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{CommandFactory, Parser};
use rns_interface::{
    rnode, rnode_admin,
    rnode_capabilities::{
        RNodeCapabilities, RNodeCapabilityParseError, RNodeKnownRadioCapabilities,
        RNodeRadioAdmission, RNodeRadioCapabilities, RNodeRadioFamily, admit_rnode_radio_settings,
        classify_rnode_radio_capabilities, parse_rnode_capabilities, rnode_product_name,
    },
    rnode_protocol::{
        FREQUENCY_TOLERANCE_HZ, RNodeFirmwareVersion, RNodeProtocolEffect, RNodeProtocolState,
        RNodeProtocolTarget, RNodeReadiness,
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
#[path = "rnodeconf/plan.rs"]
mod plan;
#[path = "rnodeconf/session.rs"]
mod session;
#[allow(dead_code)]
#[path = "rnodeconf/trust.rs"]
mod trust;

use plan::{DevicePlan, MutationPlan};
use session::{FrameSession, SerialFrameSession};

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
    if args.trust_key.is_some() {
        eprintln!(
            "rnodeconf-rs: --trust-key is not yet safely supported; validated DER key enrollment is required"
        );
        return ExitCode::from(2);
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

    let plan = match DevicePlan::build(&args) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("rnodeconf-rs: {e}");
            return ExitCode::from(2);
        }
    };
    if plan.is_empty() {
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

    let port = match serialport::new(port_path.to_string_lossy(), 115200)
        .timeout(Duration::from_millis(250))
        .open()
    {
        Ok(port) => port,
        Err(e) => {
            eprintln!("rnodeconf-rs: could not open {}: {e}", port_path.display());
            return ExitCode::from(1);
        }
    };

    let mut session = SerialFrameSession::new(port);
    if let Some(mutation) = plan.mutation {
        match execute_mutation(&mut session, mutation) {
            Ok(outcome) => println!(
                "{} ({})",
                outcome.summary(),
                model_verification_summary(outcome.verification)
            ),
            Err(error) => {
                eprintln!("rnodeconf-rs: {error}");
                return ExitCode::from(1);
            }
        }
    }

    let responses = match execute_read_only(&mut session, &plan.read_only) {
        Ok(responses) => responses,
        Err(error) => {
            eprintln!("rnodeconf-rs: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = print_responses(&responses, &args, cache_paths.as_ref()) {
        eprintln!("rnodeconf-rs: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn frame(command: u8, payload: &[u8]) -> rnode_admin::AdminFrame {
    rnode_admin::AdminFrame {
        command,
        payload: payload.to_vec(),
    }
}

const RESPONSE_TIMEOUT: Duration = Duration::from_millis(750);

#[derive(Debug, Clone, PartialEq, Eq)]
enum MutationError {
    Failed(String),
    PersistenceIndeterminate(String),
}

impl std::fmt::Display for MutationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(message) => formatter.write_str(message),
            Self::PersistenceIndeterminate(message) => write!(
                formatter,
                "persistence result is indeterminate because the device may have applied the command: {message}"
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutationKind {
    Tnc,
    Normal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MutationOutcome {
    kind: MutationKind,
    verification: RNodeRadioAdmission,
}

impl MutationOutcome {
    const fn summary(self) -> &'static str {
        match self.kind {
            MutationKind::Tnc => "TNC startup configuration saved and read back successfully",
            MutationKind::Normal => "Normal startup mode deleted and read back successfully",
        }
    }
}

fn model_verification_summary(admission: RNodeRadioAdmission) -> String {
    let product = admission.product_code();
    let model = admission.model_code();
    if admission.is_verified() {
        format!("model-specific limits verified for product 0x{product:02x}, model 0x{model:02x}")
    } else {
        format!(
            "generic RF validation only; model-specific limits unverified for product 0x{product:02x}, model 0x{model:02x}"
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct MutationPreflight {
    firmware: RNodeFirmwareVersion,
    capabilities: RNodeCapabilities,
}

fn execute_mutation<S: FrameSession>(
    session: &mut S,
    mutation: MutationPlan,
) -> Result<MutationOutcome, MutationError> {
    let preflight = mutation_preflight(session)?;
    match mutation {
        MutationPlan::Tnc(settings) => execute_tnc(session, settings, preflight),
        MutationPlan::Normal => execute_normal(session, preflight),
    }
}

fn mutation_preflight<S: FrameSession>(
    session: &mut S,
) -> Result<MutationPreflight, MutationError> {
    let detect = send_and_expect(
        session,
        &frame(rnode::CMD_DETECT, &[rnode::DETECT_REQ]),
        "RNode detection",
        |payload| {
            if payload == [rnode::DETECT_RESP] {
                Ok(())
            } else {
                Err("detection response did not identify an RNode".to_string())
            }
        },
    )
    .map_err(MutationError::Failed)?;
    debug_assert_eq!(detect.command, rnode::CMD_DETECT);

    let firmware_frame = send_and_expect(
        session,
        &frame(rnode::CMD_FW_VERSION, &[0]),
        "firmware version",
        |payload| exact_width(payload, 2, "firmware version"),
    )
    .map_err(MutationError::Failed)?;
    let firmware = RNodeFirmwareVersion::new(firmware_frame.payload[0], firmware_frame.payload[1]);
    if !firmware.is_supported() {
        return Err(MutationError::Failed(format!(
            "unsupported RNode firmware {}.{}; minimum is {}.{}",
            firmware.major,
            firmware.minor,
            RNodeFirmwareVersion::MINIMUM_SUPPORTED.major,
            RNodeFirmwareVersion::MINIMUM_SUPPORTED.minor
        )));
    }

    let eeprom_frame = send_and_expect(
        session,
        &rnode_admin::eeprom_read_frame(),
        "EEPROM identity",
        |payload| {
            eeprom::EepromImage::new(payload.to_vec())
                .map(|_| ())
                .map_err(|error| format!("malformed EEPROM response: {error}"))
        },
    )
    .map_err(MutationError::Failed)?;
    let capabilities = parse_rnode_capabilities(&eeprom_frame.payload)
        .map_err(|error| MutationError::Failed(format!("invalid EEPROM identity: {error}")))?;

    Ok(MutationPreflight {
        firmware,
        capabilities,
    })
}

fn execute_tnc<S: FrameSession>(
    session: &mut S,
    settings: rnode::RNodeRadioSettings,
    preflight: MutationPreflight,
) -> Result<MutationOutcome, MutationError> {
    let verification = admit_rnode_radio_settings(preflight.capabilities, settings)
        .map_err(|error| MutationError::Failed(error.to_string()))?;
    let target = RNodeProtocolTarget::new(
        settings.frequency,
        settings.bandwidth,
        settings.spreading_factor,
        settings.coding_rate,
        settings.tx_power,
    );
    let mut reducer = RNodeProtocolState::new(target);
    reducer.apply_frame(rnode::CMD_DETECT, &[rnode::DETECT_RESP]);
    reducer.apply_frame(
        rnode::CMD_FW_VERSION,
        &[preflight.firmware.major, preflight.firmware.minor],
    );

    let radio_frames =
        rnode_admin::decode_frames(&rnode::build_radio_configuration_sequence(&settings));
    if radio_frames.len() != 7 {
        return Err(MutationError::Failed(
            "internal radio planner produced an unexpected command count".to_string(),
        ));
    }
    for request in &radio_frames {
        let response = send_and_expect(
            session,
            request,
            radio_stage_name(request.command),
            |payload| validate_radio_echo(request, payload),
        )
        .map_err(MutationError::Failed)?;
        if matches!(
            reducer.apply_frame(response.command, &response.payload),
            RNodeProtocolEffect::Rejected(_)
        ) {
            return Err(MutationError::Failed(format!(
                "malformed {} echo",
                radio_stage_name(request.command)
            )));
        }
    }
    if reducer.readiness() != RNodeReadiness::Ready {
        return Err(MutationError::Failed(format!(
            "radio reducer did not reach Ready: {:?}",
            reducer.readiness()
        )));
    }

    let image = persist_then_read(session, rnode::CMD_CONF_SAVE)?;
    let Some(saved) = image.radio_config() else {
        return Err(MutationError::PersistenceIndeterminate(
            "EEPROM readback did not contain the saved-configuration marker".to_string(),
        ));
    };
    verify_saved_radio(&settings, &saved).map_err(MutationError::PersistenceIndeterminate)?;

    Ok(MutationOutcome {
        kind: MutationKind::Tnc,
        verification,
    })
}

fn execute_normal<S: FrameSession>(
    session: &mut S,
    preflight: MutationPreflight,
) -> Result<MutationOutcome, MutationError> {
    let verification = classify_rnode_radio_capabilities(preflight.capabilities);
    let image = persist_then_read(session, rnode::CMD_CONF_DELETE)?;
    if image.radio_config().is_some() {
        return Err(MutationError::PersistenceIndeterminate(
            "EEPROM readback still contains the saved-configuration marker".to_string(),
        ));
    }
    Ok(MutationOutcome {
        kind: MutationKind::Normal,
        verification,
    })
}

fn persist_then_read<S: FrameSession>(
    session: &mut S,
    persist_command: u8,
) -> Result<eeprom::EepromImage, MutationError> {
    session
        .send(&frame(persist_command, &[0]))
        .map_err(MutationError::PersistenceIndeterminate)?;
    let readback = send_and_expect(
        session,
        &rnode_admin::eeprom_read_frame(),
        "persisted EEPROM readback",
        |payload| {
            eeprom::EepromImage::new(payload.to_vec())
                .map(|_| ())
                .map_err(|error| format!("malformed EEPROM readback: {error}"))
        },
    )
    .map_err(MutationError::PersistenceIndeterminate)?;
    eeprom::EepromImage::new(readback.payload)
        .map_err(|error| MutationError::PersistenceIndeterminate(error.to_string()))
}

fn verify_saved_radio(
    expected: &rnode::RNodeRadioSettings,
    saved: &eeprom::RadioConfig,
) -> Result<(), String> {
    if saved.frequency.abs_diff(expected.frequency) > FREQUENCY_TOLERANCE_HZ {
        return Err(format!(
            "saved frequency mismatch: requested {}, read back {}",
            expected.frequency, saved.frequency
        ));
    }
    for (name, observed, wanted) in [
        (
            "bandwidth",
            u64::from(saved.bandwidth),
            u64::from(expected.bandwidth),
        ),
        (
            "spreading factor",
            u64::from(saved.spreading_factor),
            u64::from(expected.spreading_factor),
        ),
        (
            "coding rate",
            u64::from(saved.coding_rate),
            u64::from(expected.coding_rate),
        ),
        (
            "TX power",
            u64::from(saved.tx_power),
            u64::from(expected.tx_power),
        ),
    ] {
        if observed != wanted {
            return Err(format!(
                "saved {name} mismatch: requested {wanted}, read back {observed}"
            ));
        }
    }
    Ok(())
}

fn radio_stage_name(command: u8) -> &'static str {
    match command {
        rnode::CMD_FREQUENCY => "frequency",
        rnode::CMD_BANDWIDTH => "bandwidth",
        rnode::CMD_SF => "spreading factor",
        rnode::CMD_CR => "coding rate",
        rnode::CMD_TXPOWER => "TX power",
        rnode::CMD_RADIO_STATE => "radio state",
        _ => "radio configuration",
    }
}

fn validate_radio_echo(request: &rnode_admin::AdminFrame, payload: &[u8]) -> Result<(), String> {
    if payload.len() != request.payload.len() {
        return Err(format!(
            "malformed {} echo: expected {} bytes, got {}",
            radio_stage_name(request.command),
            request.payload.len(),
            payload.len()
        ));
    }
    if request.command == rnode::CMD_FREQUENCY {
        let wanted =
            u32::from_be_bytes(request.payload.as_slice().try_into().expect("width known"));
        let observed = u32::from_be_bytes(payload.try_into().expect("width checked"));
        if observed.abs_diff(wanted) <= FREQUENCY_TOLERANCE_HZ {
            return Ok(());
        }
    } else if payload == request.payload {
        return Ok(());
    }
    Err(format!(
        "{} echo did not match the requested value",
        radio_stage_name(request.command)
    ))
}

fn send_and_expect<S, F>(
    session: &mut S,
    request: &rnode_admin::AdminFrame,
    stage: &str,
    validate: F,
) -> Result<rnode_admin::AdminFrame, String>
where
    S: FrameSession,
    F: Fn(&[u8]) -> Result<(), String>,
{
    session.send(request)?;
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    loop {
        let Some(response) = session.receive_until(deadline)? else {
            return Err(format!("timed out waiting for {stage} response"));
        };
        if response.command == rnode::CMD_ERROR {
            return Err(format!(
                "device reported CMD_ERROR while waiting for {stage}"
            ));
        }
        if response.command != request.command {
            continue;
        }
        validate(&response.payload)?;
        return Ok(response);
    }
}

fn exact_width(payload: &[u8], expected: usize, name: &str) -> Result<(), String> {
    if payload.len() == expected {
        Ok(())
    } else {
        Err(format!(
            "malformed {name} response: expected {expected} bytes, got {}",
            payload.len()
        ))
    }
}

fn execute_read_only<S: FrameSession>(
    session: &mut S,
    requests: &[rnode_admin::AdminFrame],
) -> Result<Vec<rnode_admin::AdminFrame>, String> {
    let mut responses = Vec::with_capacity(requests.len());
    for request in requests {
        responses.push(send_and_expect(
            session,
            request,
            "read-only command",
            |payload| validate_read_only_reply(request, payload),
        )?);
    }
    Ok(responses)
}

fn validate_read_only_reply(
    request: &rnode_admin::AdminFrame,
    payload: &[u8],
) -> Result<(), String> {
    match request.command {
        rnode::CMD_DETECT if payload != [rnode::DETECT_RESP] => {
            Err("detection response did not identify an RNode".to_string())
        }
        rnode::CMD_FW_VERSION => exact_width(payload, 2, "firmware version"),
        rnode::CMD_PLATFORM | rnode::CMD_MCU | rnode::CMD_BOARD => {
            exact_width(payload, 1, "hardware identity")
        }
        rnode::CMD_DEV_HASH => exact_width(payload, 32, "device hash"),
        rnode::CMD_HASHES => {
            exact_width(payload, 33, "firmware hash")?;
            if payload.first() == request.payload.first() {
                Ok(())
            } else {
                Err("firmware hash response selector did not match request".to_string())
            }
        }
        rnode::CMD_CFG_READ if !payload.is_empty() && payload.len() < eeprom::ADDR_CONF_NM + 4 => {
            Err(format!(
                "configuration sector response is too short: {} bytes",
                payload.len()
            ))
        }
        rnode::CMD_ROM_READ => eeprom::EepromImage::new(payload.to_vec())
            .map(|_| ())
            .map_err(|error| format!("malformed EEPROM response: {error}")),
        _ => Ok(()),
    }
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
            rnode::CMD_HASHES if frame.payload.len() == 33 => {
                let label = match frame.payload[0] {
                    1 => "Target firmware hash",
                    2 => "Firmware hash",
                    _ => "Unknown firmware hash",
                };
                println!("{label}: {}", hex::encode(&frame.payload[1..]));
            }
            rnode::CMD_CFG_READ => {
                println!(
                    "Config sector: {}",
                    format_config_sector(&frame.payload, args.show_psk)
                );
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

fn format_config_sector(payload: &[u8], show_psk: bool) -> String {
    if show_psk || payload.len() <= eeprom::ADDR_CONF_PSK {
        return hex::encode(payload);
    }
    let redaction_end = eeprom::ADDR_CONF_IP.min(payload.len());
    format!(
        "{}<psk-redacted>{}",
        hex::encode(&payload[..eeprom::ADDR_CONF_PSK]),
        hex::encode(&payload[redaction_end..])
    )
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
    use std::collections::VecDeque;

    use super::*;

    type Reply = Result<Option<rnode_admin::AdminFrame>, String>;

    #[derive(Default)]
    struct ScriptedSession {
        sent: Vec<rnode_admin::AdminFrame>,
        replies: VecDeque<Reply>,
        fail_send_at: Option<(usize, &'static str)>,
    }

    impl ScriptedSession {
        fn from_frames(frames: Vec<rnode_admin::AdminFrame>) -> Self {
            Self {
                replies: frames.into_iter().map(|frame| Ok(Some(frame))).collect(),
                ..Self::default()
            }
        }

        fn from_replies(replies: Vec<Reply>) -> Self {
            Self {
                replies: replies.into(),
                ..Self::default()
            }
        }

        fn commands(&self) -> Vec<u8> {
            self.sent.iter().map(|frame| frame.command).collect()
        }
    }

    impl FrameSession for ScriptedSession {
        fn send(&mut self, frame: &rnode_admin::AdminFrame) -> Result<(), String> {
            if let Some((index, message)) = self.fail_send_at {
                if self.sent.len() == index {
                    return Err(message.to_string());
                }
            }
            self.sent.push(frame.clone());
            Ok(())
        }

        fn receive_until(
            &mut self,
            _deadline: Instant,
        ) -> Result<Option<rnode_admin::AdminFrame>, String> {
            self.replies.pop_front().unwrap_or(Ok(None))
        }
    }

    fn settings(frequency: u32) -> rnode::RNodeRadioSettings {
        rnode::RNodeRadioSettings::new(frequency, 125_000, 7, 5, 14)
    }

    fn radio_config(settings: rnode::RNodeRadioSettings) -> eeprom::RadioConfig {
        eeprom::RadioConfig {
            spreading_factor: settings.spreading_factor,
            coding_rate: settings.coding_rate,
            tx_power: settings.tx_power,
            bandwidth: settings.bandwidth,
            frequency: settings.frequency,
        }
    }

    fn provisioned_eeprom(model_code: u8, saved: Option<&eeprom::RadioConfig>) -> Vec<u8> {
        let identity = eeprom::IdentityInfo {
            product: model::PRODUCT_RNODE,
            model: model_code,
            hw_rev: 2,
            serial: 0x0102_0304,
            made: 0x6553_F100,
        };
        let mut bytes = vec![0xFF; eeprom::EEPROM_SIZE];
        let mut writes = eeprom::identity_write_frames(&identity);
        if let Some(saved) = saved {
            writes.extend(eeprom::radio_config_write_frames(saved));
        }
        for write in writes {
            assert_eq!(write.command, rnode::CMD_ROM_WRITE);
            bytes[usize::from(write.payload[0])] = write.payload[1];
        }
        bytes
    }

    fn preflight_frames(model_code: u8) -> Vec<rnode_admin::AdminFrame> {
        vec![
            frame(rnode::CMD_DETECT, &[rnode::DETECT_RESP]),
            frame(rnode::CMD_FW_VERSION, &[1, 74]),
            frame(rnode::CMD_ROM_READ, &provisioned_eeprom(model_code, None)),
        ]
    }

    fn radio_echoes(settings: rnode::RNodeRadioSettings) -> Vec<rnode_admin::AdminFrame> {
        rnode_admin::decode_frames(&rnode::build_radio_configuration_sequence(&settings))
    }

    fn successful_tnc_frames(
        model_code: u8,
        settings: rnode::RNodeRadioSettings,
        saved: eeprom::RadioConfig,
    ) -> Vec<rnode_admin::AdminFrame> {
        let mut frames = preflight_frames(model_code);
        frames.extend(radio_echoes(settings));
        frames.push(frame(
            rnode::CMD_ROM_READ,
            &provisioned_eeprom(model_code, Some(&saved)),
        ));
        frames
    }

    fn assert_no_save(session: &ScriptedSession) {
        assert!(
            session
                .sent
                .iter()
                .all(|frame| frame.command != rnode::CMD_CONF_SAVE),
            "CONF_SAVE must not follow a failed stage: {:?}",
            session.sent
        );
    }

    #[test]
    fn tnc_uses_canonical_order_and_readback_without_fabricated_save_echo() {
        let settings = settings(433_000_000);
        let mut session = ScriptedSession::from_frames(successful_tnc_frames(
            0xB4,
            settings,
            radio_config(settings),
        ));

        let outcome = execute_mutation(&mut session, MutationPlan::Tnc(settings)).unwrap();

        assert_eq!(outcome.kind, MutationKind::Tnc);
        assert!(matches!(
            outcome.verification,
            RNodeRadioAdmission::Verified {
                model_code: 0xB4,
                ..
            }
        ));
        assert_eq!(
            model_verification_summary(outcome.verification),
            "model-specific limits verified for product 0x03, model 0xb4"
        );
        assert_eq!(
            session.commands(),
            vec![
                rnode::CMD_DETECT,
                rnode::CMD_FW_VERSION,
                rnode::CMD_ROM_READ,
                rnode::CMD_RADIO_STATE,
                rnode::CMD_FREQUENCY,
                rnode::CMD_BANDWIDTH,
                rnode::CMD_SF,
                rnode::CMD_CR,
                rnode::CMD_TXPOWER,
                rnode::CMD_RADIO_STATE,
                rnode::CMD_CONF_SAVE,
                rnode::CMD_ROM_READ,
            ]
        );
        assert_eq!(
            session
                .sent
                .iter()
                .filter(|frame| frame.command == rnode::CMD_CONF_SAVE)
                .count(),
            1
        );
        assert!(
            session.replies.is_empty(),
            "success script contains no fabricated CONF_SAVE reply"
        );
    }

    #[test]
    fn pre_save_transport_and_protocol_failures_never_send_save() {
        let settings = settings(433_000_000);
        let base: Vec<Reply> = preflight_frames(0xB4)
            .into_iter()
            .map(|frame| Ok(Some(frame)))
            .collect();
        let cases: Vec<(&str, Vec<Reply>, Option<&'static str>)> = vec![
            ("write", base.clone(), Some("serial write failed: injected")),
            ("flush", base.clone(), Some("serial flush failed: injected")),
            (
                "read",
                base.iter()
                    .cloned()
                    .chain([Err("serial read failed: injected".to_string())])
                    .collect(),
                None,
            ),
            (
                "timeout",
                base.iter().cloned().chain([Ok(None)]).collect(),
                None,
            ),
            (
                "malformed",
                base.iter()
                    .cloned()
                    .chain([Ok(Some(frame(rnode::CMD_RADIO_STATE, &[])))])
                    .collect(),
                None,
            ),
            (
                "mismatch",
                base.iter()
                    .cloned()
                    .chain([Ok(Some(frame(
                        rnode::CMD_RADIO_STATE,
                        &[rnode::RADIO_STATE_ON],
                    )))])
                    .collect(),
                None,
            ),
            (
                "raw CMD_ERROR",
                base.iter()
                    .cloned()
                    .chain([Ok(Some(frame(rnode::CMD_ERROR, &[0xFE, 0xED])))])
                    .collect(),
                None,
            ),
        ];

        for (name, replies, send_error) in cases {
            let mut session = ScriptedSession::from_replies(replies);
            if let Some(message) = send_error {
                session.fail_send_at = Some((3, message));
            }
            let error =
                execute_mutation(&mut session, MutationPlan::Tnc(settings)).expect_err(name);
            assert!(
                matches!(error, MutationError::Failed(_)),
                "{name}: {error:?}"
            );
            assert_no_save(&session);
        }
    }

    #[test]
    fn detection_firmware_and_identity_failures_never_reach_radio_or_save() {
        let settings = settings(433_000_000);
        let invalid_eeprom = vec![0; eeprom::EEPROM_SIZE];
        let cases = vec![
            vec![frame(rnode::CMD_DETECT, &[0])],
            vec![
                frame(rnode::CMD_DETECT, &[rnode::DETECT_RESP]),
                frame(rnode::CMD_FW_VERSION, &[1, 51]),
            ],
            vec![
                frame(rnode::CMD_DETECT, &[rnode::DETECT_RESP]),
                frame(rnode::CMD_FW_VERSION, &[1, 74]),
                frame(rnode::CMD_ROM_READ, &invalid_eeprom),
            ],
        ];

        for frames in cases {
            let mut session = ScriptedSession::from_frames(frames);
            assert!(matches!(
                execute_mutation(&mut session, MutationPlan::Tnc(settings)),
                Err(MutationError::Failed(_))
            ));
            assert_no_save(&session);
            assert!(
                session
                    .sent
                    .iter()
                    .all(|request| request.command != rnode::CMD_FREQUENCY)
            );
        }
    }

    #[test]
    fn every_radio_stage_mismatch_stops_before_later_stages_and_save() {
        let settings = settings(433_000_000);
        let echoes = radio_echoes(settings);
        for failed_index in 0..echoes.len() {
            let mut frames = preflight_frames(0xB4);
            frames.extend(echoes[..failed_index].iter().cloned());
            let mut wrong = echoes[failed_index].clone();
            if matches!(wrong.command, rnode::CMD_FREQUENCY | rnode::CMD_BANDWIDTH) {
                let value = u32::from_be_bytes(wrong.payload.as_slice().try_into().unwrap());
                let delta = if wrong.command == rnode::CMD_FREQUENCY {
                    FREQUENCY_TOLERANCE_HZ + 1
                } else {
                    1
                };
                wrong.payload = (value + delta).to_be_bytes().to_vec();
            } else {
                wrong.payload[0] ^= 1;
            }
            frames.push(wrong);
            let mut session = ScriptedSession::from_frames(frames);

            assert!(matches!(
                execute_mutation(&mut session, MutationPlan::Tnc(settings)),
                Err(MutationError::Failed(_))
            ));
            assert_no_save(&session);
            assert_eq!(session.sent.len(), 3 + failed_index + 1);
        }
    }

    #[test]
    fn frequency_tolerance_is_accepted_for_echo_and_persisted_readback() {
        let settings = settings(433_000_000);
        let mut saved = radio_config(settings);
        saved.frequency += FREQUENCY_TOLERANCE_HZ;
        let mut frames = successful_tnc_frames(0xB4, settings, saved);
        frames[4].payload = (settings.frequency + FREQUENCY_TOLERANCE_HZ)
            .to_be_bytes()
            .to_vec();
        let mut session = ScriptedSession::from_frames(frames);

        assert!(execute_mutation(&mut session, MutationPlan::Tnc(settings)).is_ok());
    }

    #[test]
    fn every_post_save_verification_failure_is_indeterminate() {
        let settings = settings(433_000_000);
        let mut prefix: Vec<Reply> = preflight_frames(0xB4)
            .into_iter()
            .chain(radio_echoes(settings))
            .map(|frame| Ok(Some(frame)))
            .collect();
        let mut mismatch = radio_config(settings);
        mismatch.bandwidth += 1;
        let cases: Vec<(&str, Reply)> = vec![
            (
                "marker absent",
                Ok(Some(frame(
                    rnode::CMD_ROM_READ,
                    &provisioned_eeprom(0xB4, None),
                ))),
            ),
            (
                "value mismatch",
                Ok(Some(frame(
                    rnode::CMD_ROM_READ,
                    &provisioned_eeprom(0xB4, Some(&mismatch)),
                ))),
            ),
            ("timeout", Ok(None)),
            ("read", Err("serial read failed: injected".to_string())),
            ("device error", Ok(Some(frame(rnode::CMD_ERROR, &[0x7F])))),
            (
                "malformed readback",
                Ok(Some(frame(rnode::CMD_ROM_READ, &[0; 8]))),
            ),
        ];

        for (name, final_reply) in cases {
            let mut replies = prefix.clone();
            replies.push(final_reply);
            let mut session = ScriptedSession::from_replies(replies);
            let error =
                execute_mutation(&mut session, MutationPlan::Tnc(settings)).expect_err(name);
            assert!(
                matches!(error, MutationError::PersistenceIndeterminate(_)),
                "{name}: {error:?}"
            );
            assert!(
                session
                    .sent
                    .iter()
                    .any(|request| request.command == rnode::CMD_CONF_SAVE)
            );
        }
        prefix.clear();
    }

    #[test]
    fn normal_delete_requires_readback_marker_to_be_absent() {
        let mut frames = preflight_frames(0xB4);
        frames.push(frame(rnode::CMD_ROM_READ, &provisioned_eeprom(0xB4, None)));
        let mut success = ScriptedSession::from_frames(frames);
        let outcome = execute_mutation(&mut success, MutationPlan::Normal).unwrap();
        assert_eq!(outcome.kind, MutationKind::Normal);
        assert_eq!(
            &success.commands()[3..],
            &[rnode::CMD_CONF_DELETE, rnode::CMD_ROM_READ]
        );

        let settings = settings(433_000_000);
        let mut frames = preflight_frames(0xB4);
        frames.push(frame(
            rnode::CMD_ROM_READ,
            &provisioned_eeprom(0xB4, Some(&radio_config(settings))),
        ));
        let mut failure = ScriptedSession::from_frames(frames);
        assert!(matches!(
            execute_mutation(&mut failure, MutationPlan::Normal),
            Err(MutationError::PersistenceIndeterminate(_))
        ));
    }

    #[test]
    fn model_gate_enforces_known_limits_and_labels_quarantine_honestly() {
        let unsupported = settings(868_000_000);
        let mut known = ScriptedSession::from_frames(preflight_frames(0xB4));
        let error = execute_mutation(&mut known, MutationPlan::Tnc(unsupported)).unwrap_err();
        assert_eq!(
            error,
            MutationError::Failed(
                "frequency 868000000 Hz is outside verified model range 420000000..=520000000 Hz"
                    .to_string()
            )
        );
        assert_no_save(&known);
        assert!(
            known
                .sent
                .iter()
                .all(|request| request.command != rnode::CMD_FREQUENCY)
        );

        let excessive_power = rnode::RNodeRadioSettings::new(433_000_000, 125_000, 7, 5, 18);
        let mut known = ScriptedSession::from_frames(preflight_frames(0xB4));
        let error = execute_mutation(&mut known, MutationPlan::Tnc(excessive_power)).unwrap_err();
        assert_eq!(
            error,
            MutationError::Failed(
                "TX power 18 dBm exceeds verified model maximum 17 dBm".to_string()
            )
        );
        assert_no_save(&known);
        assert!(
            known
                .sent
                .iter()
                .all(|request| request.command != rnode::CMD_FREQUENCY)
        );

        let mut quarantined = ScriptedSession::from_frames(successful_tnc_frames(
            0xA6,
            unsupported,
            radio_config(unsupported),
        ));
        let outcome = execute_mutation(&mut quarantined, MutationPlan::Tnc(unsupported)).unwrap();
        assert!(matches!(
            outcome.verification,
            RNodeRadioAdmission::Unverified {
                model_code: 0xA6,
                ..
            }
        ));
        assert_eq!(
            model_verification_summary(outcome.verification),
            "generic RF validation only; model-specific limits unverified for product 0x03, model 0xa6"
        );
    }

    #[test]
    fn unrelated_telemetry_cannot_satisfy_an_expected_reply() {
        let request = frame(rnode::CMD_CFG_READ, &[0]);
        let config = vec![0; eeprom::ADDR_CONF_NM + 4];
        let mut session = ScriptedSession::from_frames(vec![
            frame(rnode::CMD_READY, &[1]),
            frame(rnode::CMD_CFG_READ, &config),
        ]);
        let responses = execute_read_only(&mut session, std::slice::from_ref(&request)).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].command, rnode::CMD_CFG_READ);
        assert_eq!(session.sent, vec![request.clone()]);

        let mut only_telemetry =
            ScriptedSession::from_replies(vec![Ok(Some(frame(rnode::CMD_READY, &[1]))), Ok(None)]);
        assert!(
            execute_read_only(&mut only_telemetry, &[request])
                .unwrap_err()
                .contains("timed out")
        );
    }

    #[test]
    fn read_only_hash_shape_and_selector_are_strict() {
        let request = frame(rnode::CMD_HASHES, &[1]);
        let mut payload = vec![1];
        payload.extend([0xA5; 32]);
        let mut session = ScriptedSession::from_frames(vec![frame(rnode::CMD_HASHES, &payload)]);
        assert!(execute_read_only(&mut session, std::slice::from_ref(&request)).is_ok());

        payload[0] = 2;
        let mut wrong_selector =
            ScriptedSession::from_frames(vec![frame(rnode::CMD_HASHES, &payload)]);
        assert!(
            execute_read_only(&mut wrong_selector, &[request])
                .unwrap_err()
                .contains("selector")
        );
    }

    #[test]
    fn config_accepts_documented_empty_sector_and_rejects_partial_sector() {
        let request = frame(rnode::CMD_CFG_READ, &[0]);
        let mut empty = ScriptedSession::from_frames(vec![frame(rnode::CMD_CFG_READ, &[])]);
        assert!(execute_read_only(&mut empty, std::slice::from_ref(&request)).is_ok());

        let mut partial = ScriptedSession::from_frames(vec![frame(rnode::CMD_CFG_READ, &[0; 8])]);
        assert!(execute_read_only(&mut partial, &[request]).is_err());
    }

    #[test]
    fn config_psk_redaction_covers_the_full_33_byte_slot() {
        let mut config = vec![0; eeprom::ADDR_CONF_NM + 4];
        config[eeprom::ADDR_CONF_PSK..eeprom::ADDR_CONF_IP].fill(0xAB);
        config[eeprom::ADDR_CONF_IP - 1] = 0xCD;

        let redacted = format_config_sector(&config, false);
        assert!(redacted.contains("<psk-redacted>"));
        assert!(!redacted.contains("abab"));
        assert!(!redacted.contains("cd"));
        let visible = format_config_sector(&config, true);
        assert!(visible.contains("abab"));
        assert!(visible.contains("cd"));
    }

    #[test]
    fn eeprom_summary_retains_validated_capability_and_startup_information() {
        let settings = settings(433_000_000);
        let image =
            eeprom::EepromImage::new(provisioned_eeprom(0xB4, Some(&radio_config(settings))))
                .unwrap();
        let lines = eeprom_summary_lines(&image);

        assert!(lines.iter().any(|line| line == "  Model: 0xb4"));
        assert!(lines.iter().any(|line| line == "  Radio family: SX1278"));
        assert!(lines.iter().any(|line| line.contains("Startup mode: TNC")));
    }
}
