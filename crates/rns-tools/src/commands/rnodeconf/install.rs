//! Firmware flows of upstream `rnodeconf`: `-u`/`-U` update, `-f` flash,
//! `-e` extraction and `-E` use of an extracted firmware.

use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use rns_interface::rnode_admin;

use super::firmware::{self, CachePaths, EXTRACTED_FIRMWARE, Selection, Source};
use super::flash::{self, FlashContext};
use super::session::RNode;
use super::{Args, Device, ParsedEeprom, graceful_exit, log, model, out};

/// Never equal to a platform code: upstream compares the `--platform` string
/// with integer platform codes, so a given `--platform` matches no flasher.
const UNMATCHED_PLATFORM: u8 = 0x00;

/// What upstream does after its update block.
pub enum UpdateStep {
    Exit(ExitCode),
    /// Continue `main()` with this session; `info` is upstream's `args.info`.
    Continue {
        rnode: Box<RNode>,
        info: bool,
        device: Option<Device>,
    },
}

/// Flows that download or unpack firmware, refused when built without it.
pub fn feature_refusal(args: &Args) -> Option<&'static str> {
    let needed = args.update || args.flash || args.autoinstall;
    (needed && !cfg!(feature = "rnodeconf-firmware")).then_some(firmware::NO_FIRMWARE_SUPPORT)
}

fn cache_paths() -> Result<CachePaths, String> {
    super::rnodeconf_cache_paths()
}

fn source(args: &Args) -> Source<'_> {
    Source {
        fw_url: args.fw_url.as_deref(),
        nocheck: args.nocheck,
    }
}

fn flash_context(args: &Args, port: &str, paths: &CachePaths, version: &str) -> FlashContext {
    FlashContext {
        python: "python3".to_string(),
        port: port.to_string(),
        baud_flash: args.baud_flash.clone(),
        update_dir: paths.update.clone(),
        extracted_dir: paths.extracted.clone(),
        selected_version: version.to_string(),
    }
}

fn read_enter() -> Result<(), String> {
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) => Err("EOF when reading a line".to_string()),
        Ok(_) => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn open_session(port: &str) -> Result<RNode, String> {
    rns_interface::serial::open_port(
        serialport::new(port, 115200).timeout(Duration::from_millis(100)),
    )
    .map(|serial| RNode::new(serial, port.to_string()))
    .map_err(|e| e.to_string())
}

/// Upstream's `-E` warning, shown before an update or autoinstall.
pub fn use_extracted_warning(args: &Args) -> Result<(), String> {
    if !(args.use_extracted && ((args.update && args.port.is_some()) || args.autoinstall)) {
        return Ok(());
    }
    for line in [
        "",
        "You have specified that rnodeconf should use a firmware extracted",
        "from another device. Please note that this *only* works if you are",
        "targeting a device of the same type that the firmware came from!",
        "",
        "Flashing this firmware to a device it was not created for will most",
        "likely result in it being inoperable until it is updated with the",
        "correct firmware. Hit enter to continue.",
    ] {
        out(line);
    }
    read_enter()
}

/// The firmware file upstream picks for a provisioned device before `-u`.
fn update_filename(rnode: &RNode, device: &Device, args: &Args) -> Option<&'static str> {
    if device.model != 0xFF {
        return model::model_info(device.model).and_then(|info| info.firmware_filename);
    }
    if args.use_extracted {
        return Some(EXTRACTED_FIRMWARE);
    }
    match (rnode.platform, rnode.mcu, rnode.board) {
        (Some(model::PLATFORM_AVR), Some(model::MCU_1284P), _) => Some("rnode_firmware.hex"),
        (Some(model::PLATFORM_AVR), Some(model::MCU_2560), _) => Some("rnode_firmware_m2560.hex"),
        (Some(model::PLATFORM_ESP32), _, Some(0x34)) => Some("rnode_firmware_featheresp32.zip"),
        (Some(model::PLATFORM_ESP32), _, Some(0x35)) => Some("rnode_firmware_esp32_generic.zip"),
        (Some(model::PLATFORM_NRF52), _, Some(0x51)) => Some("rnode_firmware_rak4631.zip"),
        _ => None,
    }
}

/// Upstream's `-u` block, from the provisioning check to the reconnect. The
/// session is closed before the flasher runs, as upstream's `disconnect`.
pub fn update(mut rnode: RNode, args: &Args, device: Option<Device>) -> Result<UpdateStep, String> {
    let exit = |rnode: &mut RNode, code: u8| Ok(UpdateStep::Exit(graceful_exit(rnode, code)));
    let Some(provisioned) = device.as_ref() else {
        log("Device not provisioned. Cannot update device firmware.");
        return exit(&mut rnode, 1);
    };
    let fw_filename = if args.use_extracted {
        Some(EXTRACTED_FIRMWARE)
    } else {
        update_filename(&rnode, provisioned, args)
    };
    let Some(fw_filename) = fw_filename else {
        log("ERROR: No firmware found for this board. Cannot update.");
        return exit(&mut rnode, 0);
    };
    let paths = cache_paths()?;
    let port = rnode.name.clone();

    log("Checking firmware file availability...");
    let mut selection = Selection {
        version: args.fw_version.clone(),
        hash: None,
    };
    let mut ensured = false;
    if selection.version.is_none() {
        if let Err(code) =
            firmware::ensure_firmware_file(&paths, fw_filename, &mut selection, source(args))
        {
            return exit(&mut rnode, code);
        }
        ensured = true;
    }
    let version = selection.version.clone().unwrap_or_default();
    if !args.force_update {
        let installed = rnode.version().unwrap_or_default();
        let which = if args.fw_version.is_some() {
            "Specified"
        } else {
            "Latest"
        };
        // Upstream compares the version strings, not numbers.
        let state = if installed == version {
            Some("is already installed on this device")
        } else if installed > version {
            Some("is older than firmware already installed on this device")
        } else {
            None
        };
        if let Some(state) = state {
            log(format!("{which} firmware version ({version}) {state}"));
            log("Override with -U option to install anyway");
            return exit(&mut rnode, 0);
        }
    }
    if !ensured
        && let Err(code) =
            firmware::ensure_firmware_file(&paths, fw_filename, &mut selection, source(args))
    {
        return exit(&mut rnode, code);
    }
    let version = selection.version.clone().unwrap_or_default();
    let version_dir = paths.update.join(&version);
    if fw_filename.ends_with(".zip") && fw_filename != EXTRACTED_FIRMWARE {
        log("Decompressing firmware...");
        if firmware::extract_zip(&version_dir.join(fw_filename), &version_dir).is_err() {
            log("Could not decompress firmware from downloaded zip file");
            return exit(&mut rnode, 0);
        }
        log("Firmware decompressed");
    }

    let update_full_path = if fw_filename == EXTRACTED_FIRMWARE {
        paths.extracted.join("extracted_rnode_firmware.version")
    } else {
        version_dir.join(fw_filename)
    };
    if !update_full_path.is_file() {
        log("Firmware update file not found");
        return exit(&mut rnode, 0);
    }
    log(format!("Updating RNode firmware for device on {port}"));
    let partition_hash = if fw_filename == EXTRACTED_FIRMWARE {
        let text = std::fs::read_to_string(&update_full_path).unwrap_or_default();
        text.split_whitespace()
            .nth(1)
            .and_then(super::py_fromhex)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
    } else {
        super::bootstrap::partition_hash(
            rnode.platform,
            &version_dir.join(fw_filename.replace(".zip", ".bin")),
        )
    };
    if let Some(hash) = partition_hash.as_ref() {
        if rnode
            .send_frame(&rnode_admin::firmware_update_frame())
            .is_err()
        {
            log(
                "Error while indicating firmware update start to board, attempting update anyway...",
            );
        }
        rnode.send_frame(&rnode_admin::firmware_hash_frame(hash))?;
        rnode.pump(Duration::from_secs(1))?;
        if rnode.platform == Some(model::PLATFORM_NRF52) {
            // Upstream allows extra time for the slow NRF52 EEPROM write.
            rnode.pump(Duration::from_secs(14))?;
        }
    }
    if rnode.leave().is_err() {
        log(
            "Error while gracefully disconnecting device before firmware update, attempting update anyway...",
        );
    }
    let platform = rnode.platform.unwrap_or(UNMATCHED_PLATFORM);
    drop(rnode);

    let ctx = flash_context(args, &port, &paths, &version);
    let failed = |error: String| {
        log("Error while updating firmware");
        log(error);
        Err("the firmware update did not complete".to_string())
    };
    let plan = match flash::flasher_call(platform, fw_filename, &ctx) {
        Ok(Some(plan)) => plan,
        Ok(None) => return failed("'NoneType' object is not iterable".to_string()),
        Err(code) => return Ok(UpdateStep::Exit(ExitCode::from(code))),
    };
    let status = match Command::new(&plan.program).args(&plan.args).status() {
        Ok(status) => status,
        Err(error) => return failed(error.to_string()),
    };
    if !status.success() {
        log("An error occurred while flashing the new firmware, exiting now.");
        return Ok(UpdateStep::Exit(ExitCode::SUCCESS));
    }
    log("Flashing new firmware completed");
    log(format!("Opening serial port {port}..."));
    let mut rnode = match open_session(&port) {
        Ok(rnode) => rnode,
        Err(error) => {
            log("Could not open the specified serial port. The contained exception was:");
            log(error);
            return Ok(UpdateStep::Exit(ExitCode::SUCCESS));
        }
    };
    if let Err(error) = rnode.device_probe() {
        log("Serial port opened, but RNode did not respond. Is a valid firmware installed?");
        out(error);
        return exit(&mut rnode, 0);
    }
    let mut info = false;
    let mut device = None;
    if rnode.detected == Some(true) {
        if rnode.platform.is_none() || rnode.mcu.is_none() {
            rnode.platform = Some(model::PLATFORM_AVR);
            rnode.mcu = Some(model::MCU_1284P);
        }
        log("Reading EEPROM...");
        rnode.download_eeprom()?;
        if let Some(eeprom) = rnode.eeprom.clone()
            && let ParsedEeprom::Device(Some(parsed)) = super::parse_eeprom(&eeprom, &rnode.name)
        {
            info = true;
            device = Some(parsed);
            if let Some(hash) = partition_hash.as_ref() {
                rnode.send_frame(&rnode_admin::firmware_hash_frame(hash))?;
            }
        }
    }
    if info {
        log("");
        log("Firmware update completed successfully");
    }
    Ok(UpdateStep::Continue {
        rnode: Box::new(rnode),
        info,
        device,
    })
}

/// Upstream's `-f` block, run before the port is opened. `Ok(true)` is
/// upstream setting `args.rom` after a successful flash.
pub fn flash(args: &Args, port: &str) -> Result<bool, ExitCode> {
    let platform = match args.platform {
        Some(_) => UNMATCHED_PLATFORM,
        None => model::PLATFORM_AVR,
    };
    let Some(version) = args.fw_version.as_deref() else {
        log("Missing parameters, cannot continue");
        return Err(ExitCode::from(68));
    };
    let paths = cache_paths().map_err(|error| {
        log(error);
        ExitCode::from(1)
    })?;
    flash_firmware(args, port, &paths, platform, "rnode_firmware.hex", version)
}

/// Upstream's flash step of `-f` and autoinstall for a chosen file and platform.
pub fn flash_firmware(
    args: &Args,
    port: &str,
    paths: &CachePaths,
    platform: u8,
    fw_filename: &str,
    version: &str,
) -> Result<bool, ExitCode> {
    let ctx = flash_context(args, port, paths, version);
    let extracted = fw_filename == EXTRACTED_FIRMWARE;
    if !extracted {
        let fw_src = paths.update.join(version);
        if !fw_src.join(fw_filename).is_file() {
            log("Firmware file not found");
            return Err(ExitCode::SUCCESS);
        }
        if fw_filename.ends_with(".zip") {
            log("Decompressing firmware...");
            if firmware::extract_zip(&fw_src.join(fw_filename), &fw_src).is_err() {
                log("Could not decompress firmware from downloaded zip file");
                return Err(ExitCode::SUCCESS);
            }
            log("Firmware decompressed");
        }
    }
    log(format!("Flashing RNode firmware to device on {port}"));
    let plan = match flash::flasher_call(platform, fw_filename, &ctx) {
        Ok(Some(plan)) => plan,
        Ok(None) => {
            log("Error while flashing");
            log("expected str, bytes or os.PathLike object, not NoneType");
            return Err(ExitCode::from(1));
        }
        Err(code) => return Err(ExitCode::from(code)),
    };
    let status = match Command::new(&plan.program).args(&plan.args).status() {
        Ok(status) => status,
        Err(error) => {
            log("Error while flashing");
            log(error.to_string());
            return Err(ExitCode::from(1));
        }
    };
    if !status.success() {
        if !extracted {
            log(format!(
                "Error from flasher ({}) while writing.",
                status.code().unwrap_or(-1)
            ));
            log("Some boards have trouble flashing at high speeds, and you can");
            log("try flashing with a lower baud rate, as in this example:");
            log("rnodeconf --autoinstall --baud-flash 115200");
        }
        return Err(ExitCode::SUCCESS);
    }
    log("Done flashing");
    if platform == model::PLATFORM_ESP32 {
        log("Waiting for ESP32 reset...");
        std::thread::sleep(Duration::from_secs(if extracted { 7 } else { 8 }));
    } else if platform == model::PLATFORM_NRF52 && !extracted {
        log("Waiting for NRF52 reset...");
        std::thread::sleep(Duration::from_secs(6));
    }
    Ok(true)
}

/// Upstream's `-e`: read the firmware partitions of an ESP32 RNode into the
/// extracted-firmware cache.
pub fn extract(args: &Args) -> ExitCode {
    out("");
    out("RNode Firmware Extraction");
    out("");
    let port_path = match args.port.as_deref() {
        Some(port) => {
            let listed = serialport::available_ports()
                .unwrap_or_default()
                .iter()
                .any(|info| info.port_name == port);
            if !listed {
                // Upstream reaches an unbound local here and exits 1.
                out(format!("Could not find specified port {port}, exiting now"));
                return ExitCode::from(1);
            }
            out("");
            out(format!("Using device on {port}"));
            port.to_string()
        }
        None => match choose_port() {
            Some(port) => port,
            None => return ExitCode::SUCCESS,
        },
    };
    out("");
    out("Probing device...");
    let mut rnode = match open_session(&port_path) {
        Ok(rnode) => rnode,
        Err(error) => {
            log("Could not open the specified serial port. The contained exception was:");
            log(error);
            return ExitCode::SUCCESS;
        }
    };
    if rnode.device_probe().is_err() {
        log("No answer from device");
    }
    let mut device = None;
    if rnode.detected == Some(true) {
        log("Trying to read EEPROM...");
        if rnode.download_eeprom().is_ok()
            && let Some(eeprom) = rnode.eeprom.clone()
            && let ParsedEeprom::Device(parsed) = super::parse_eeprom(&eeprom, &rnode.name)
        {
            device = parsed;
        }
    } else {
        log("Could not detect a connected RNode");
    }
    if rnode.platform != Some(model::PLATFORM_ESP32) {
        out("");
        out("Firmware extraction is currently only supported on ESP32-based RNodes.");
        return graceful_exit(&mut rnode, 170);
    }
    if let Some(device) = device.as_ref() {
        if !device.signature.valid {
            for line in [
                "\nThe device signature in this RNode is unknown and cannot be verified. It is still",
                "possible to extract the firmware from it, but you should make absolutely sure that",
                "it comes from a trusted source. It is possible that someone could have modified the",
                "firmware. If that is the case, these modifications will propagate to any new RNodes",
                "descendent from this one!",
                "\nHit enter if you are sure you want to continue.",
            ] {
                out(line);
            }
            if read_enter().is_err() {
                return ExitCode::from(1);
            }
        }
        if let Some(hash) = rnode.firmware_hash.clone() {
            let v_str = format!(
                "{} {}",
                rnode.version().unwrap_or_default(),
                hex::encode(hash)
            );
            let _ = rnode.leave();
            drop(rnode);
            out(format!("\nFound RNode Firmvare v{v_str}"));
            out("\nReady to extract firmware images from the RNode");
            out("Press enter to start the extraction process");
            if read_enter().is_err() {
                return ExitCode::from(1);
            }
            return extract_partitions(args, &port_path, &v_str);
        }
        out("Could not read firmware information from device");
    }
    out("\nRNode firmware extraction failed");
    graceful_exit(&mut rnode, 180)
}

fn extract_partitions(args: &Args, port: &str, v_str: &str) -> ExitCode {
    // Upstream runs its embedded recovery esptool; this build uses one from PATH.
    let Some(esptool) = ["esptool.py", "esptool"]
        .into_iter()
        .find(|tool| flash::which(tool).is_some())
    else {
        log("Error: Could not find esptool.py or esptool on PATH. Install it with:");
        log("  pip3 install --user esptool");
        return ExitCode::from(181);
    };
    let paths = match cache_paths() {
        Ok(paths) => paths,
        Err(error) => {
            log(error);
            return ExitCode::from(1);
        }
    };
    let _ = std::fs::create_dir_all(&paths.extracted);
    if let Err(error) = std::fs::write(
        paths.extracted.join("extracted_rnode_firmware.version"),
        v_str,
    ) {
        log(error.to_string());
        return ExitCode::from(1);
    }
    let parts = [
        (
            "bootloader",
            "0x1000",
            "0x4650",
            "extracted_rnode_firmware.bootloader",
        ),
        (
            "partition table",
            "0x8000",
            "0xC00",
            "extracted_rnode_firmware.partitions",
        ),
        (
            "app boot",
            "0xe000",
            "0x2000",
            "extracted_rnode_firmware.boot_app0",
        ),
        (
            "application image",
            "0x10000",
            "0x200000",
            "extracted_rnode_firmware.bin",
        ),
        (
            "console image",
            "0x210000",
            "0x1F0000",
            "extracted_console_image.bin",
        ),
    ];
    for (part, offset, size, file) in parts {
        out(format!("Extracting {part}..."));
        let target = paths.extracted.join(file);
        let argv = [
            "--chip",
            "esp32",
            "--port",
            port,
            "--baud",
            &args.baud_flash,
            "--before",
            "default_reset",
            "--after",
            "hard_reset",
            "read_flash",
            offset,
            size,
            &target.to_string_lossy(),
        ]
        .map(str::to_string);
        let ok = Command::new(esptool)
            .args(&argv)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if !ok {
            out(format!(
                "The extraction failed, the following command did not complete successfully:\n{esptool} {}",
                argv.join(" ")
            ));
            return ExitCode::from(182);
        }
    }
    out("\nFirmware successfully extracted!");
    out("\nYou can now use this firmware to update or autoinstall other RNodes");
    ExitCode::SUCCESS
}

/// Upstream's interactive port choice for `-e` without a port.
fn choose_port() -> Option<String> {
    let ports: Vec<_> = serialport::available_ports()
        .unwrap_or_default()
        .into_iter()
        .rev()
        .collect();
    out("Detected serial ports:");
    for (index, port) in ports.iter().enumerate() {
        out(format!("  [{}] {}", index + 1, port.port_name));
    }
    print!("\nEnter the number of the serial port your device is connected to:\n? ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let mut line = String::new();
    let chosen = std::io::stdin()
        .read_line(&mut line)
        .ok()
        .and_then(|_| line.trim().parse::<usize>().ok())
        .filter(|n| (1..=ports.len()).contains(n))
        .map(|n| ports[n - 1].port_name.clone());
    match chosen {
        Some(port) => {
            out(format!("\nOk, using device on {port}"));
            Some(port)
        }
        None => {
            out("That port does not exist, exiting now.");
            None
        }
    }
}
