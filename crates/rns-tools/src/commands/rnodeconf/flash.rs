//! Firmware flasher command lines, after upstream `rnodeconf`'s `get_flasher_call`.

use std::path::{Path, PathBuf};

use super::{log, model};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashContext {
    pub python: String,
    pub port: String,
    pub baud_flash: String,
    pub update_dir: PathBuf,
    pub extracted_dir: PathBuf,
    pub selected_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashPlan {
    pub program: String,
    pub args: Vec<String>,
}

impl FlashPlan {
    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(self.args.len() + 1);
        argv.push(self.program.clone());
        argv.extend(self.args.clone());
        argv
    }
}

/// Upstream `get_flasher_call`: the flasher must be on `PATH` (for ESP32,
/// the firmware package's `esptool.py`). `Ok(None)` is upstream returning
/// nothing for an unknown board; `Err` is its `graceful_exit` code.
pub fn flasher_call(
    platform: u8,
    fw_filename: &str,
    ctx: &FlashContext,
) -> Result<Option<FlashPlan>, u8> {
    match platform {
        model::PLATFORM_AVR | model::PLATFORM_NRF52 => {
            let (flasher, install) = if platform == model::PLATFORM_AVR {
                ("avrdude", "sudo apt install avrdude")
            } else {
                ("adafruit-nrfutil", "pip3 install --user adafruit-nrfutil")
            };
            if which(flasher).is_none() {
                missing_flasher(flasher, install);
                return Err(0);
            }
            Ok(plan_flasher(platform, fw_filename, ctx))
        }
        model::PLATFORM_ESP32 => {
            if ctx.selected_version.parse::<f64>().is_err() {
                return Ok(None);
            }
            let package_flasher = ctx
                .update_dir
                .join(&ctx.selected_version)
                .join("esptool.py");
            if package_flasher.is_file() {
                make_executable(&package_flasher);
                let plan = plan_flasher(platform, fw_filename, ctx);
                if plan.is_none() {
                    log("No flasher available for this board, cannot install firmware.");
                }
                return Ok(plan);
            }
            // Upstream falls back to its embedded recovery esptool; this build uses one from PATH.
            let Some(flasher) = ["esptool.py", "esptool"]
                .into_iter()
                .find(|f| which(f).is_some())
            else {
                missing_flasher("esptool.py", "pip3 install --user esptool");
                return Err(0);
            };
            log("No flasher present, using esptool from PATH to write firmware to device");
            let plan = plan_flasher(platform, fw_filename, ctx).map(|plan| FlashPlan {
                program: flasher.to_string(),
                args: plan.args[1..].to_vec(),
            });
            if plan.is_none() {
                log("No flasher available for this board, cannot install firmware.");
            }
            Ok(plan)
        }
        _ => Ok(None),
    }
}

fn missing_flasher(flasher: &str, install: &str) {
    log("");
    log(format!(
        "You do not currently have the \"{flasher}\" program installed on your system."
    ));
    log("Unfortunately, that means we can't proceed, since it is needed to flash your");
    log("board. You can install it via your package manager, for example:");
    log("");
    log(format!("  {install}"));
    log("");
    log(format!("Please install \"{flasher}\" and try again."));
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    // Upstream: os.chmod(flasher, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP).
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o750));
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

/// `shutil.which`: an executable file named `program` on `PATH`.
pub fn which(program: &str) -> Option<PathBuf> {
    let is_exec = |path: &Path| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            path.metadata()
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            path.is_file()
        }
    };
    let candidate = Path::new(program);
    if candidate.components().count() > 1 {
        return is_exec(candidate).then(|| candidate.to_path_buf());
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|path| is_exec(path))
}

pub fn plan_flasher(platform: u8, fw_filename: &str, ctx: &FlashContext) -> Option<FlashPlan> {
    match platform {
        model::PLATFORM_AVR => plan_avr(fw_filename, ctx),
        model::PLATFORM_ESP32 => plan_esp32(fw_filename, ctx),
        model::PLATFORM_NRF52 => Some(plan_nrf52(fw_filename, ctx)),
        _ => None,
    }
}

fn plan_avr(fw_filename: &str, ctx: &FlashContext) -> Option<FlashPlan> {
    let mut args = vec!["-P".to_string(), ctx.port.clone()];
    match fw_filename {
        "rnode_firmware.hex" => {
            args.extend([
                "-p".to_string(),
                "m1284p".to_string(),
                "-c".to_string(),
                "arduino".to_string(),
                "-b".to_string(),
                "115200".to_string(),
                "-U".to_string(),
                format!(
                    "flash:w:{}:i",
                    path_string(&ctx.update_dir.join(&ctx.selected_version).join(fw_filename))
                ),
            ]);
        }
        "rnode_firmware_m2560.hex" => {
            args.extend([
                "-p".to_string(),
                "atmega2560".to_string(),
                "-c".to_string(),
                "wiring".to_string(),
                "-D".to_string(),
                "-b".to_string(),
                "115200".to_string(),
                "-U".to_string(),
                format!(
                    "flash:w:{}",
                    path_string(&ctx.update_dir.join(&ctx.selected_version).join(fw_filename))
                ),
            ]);
        }
        _ => return None,
    }
    Some(FlashPlan {
        program: "avrdude".to_string(),
        args,
    })
}

fn plan_nrf52(fw_filename: &str, ctx: &FlashContext) -> FlashPlan {
    FlashPlan {
        program: "adafruit-nrfutil".to_string(),
        args: vec![
            "dfu".to_string(),
            "serial".to_string(),
            "--package".to_string(),
            path_string(&ctx.update_dir.join(&ctx.selected_version).join(fw_filename)),
            "-p".to_string(),
            ctx.port.clone(),
            "-b".to_string(),
            "115200".to_string(),
            "-t".to_string(),
            "1200".to_string(),
        ],
    }
}

fn plan_esp32(fw_filename: &str, ctx: &FlashContext) -> Option<FlashPlan> {
    // Upstream parses the version before choosing a board and fails on a non-number.
    let version = ctx.selected_version.parse::<f64>().ok()?;
    if fw_filename == "extracted_rnode_firmware.zip" {
        return Some(FlashPlan {
            program: ctx.python.clone(),
            args: esp32_args(
                &ctx.update_dir
                    .join(&ctx.selected_version)
                    .join("esptool.py"),
                "esp32",
                &ctx.port,
                &ctx.baud_flash,
                "4MB",
                &[
                    (
                        "0x1000",
                        ctx.extracted_dir
                            .join("extracted_rnode_firmware.bootloader"),
                    ),
                    (
                        "0xe000",
                        ctx.extracted_dir.join("extracted_rnode_firmware.boot_app0"),
                    ),
                    (
                        "0x8000",
                        ctx.extracted_dir
                            .join("extracted_rnode_firmware.partitions"),
                    ),
                    (
                        "0x10000",
                        ctx.extracted_dir.join("extracted_rnode_firmware.bin"),
                    ),
                    (
                        "0x210000",
                        ctx.extracted_dir.join("extracted_console_image.bin"),
                    ),
                ],
            ),
        });
    }

    let spec = esp32_spec(fw_filename)?;
    let version_dir = ctx.update_dir.join(&ctx.selected_version);
    let console = spec.console_from.is_none_or(|min| version >= min);
    let stem = match spec.legacy_stem {
        Some(legacy) if !console => legacy,
        _ => fw_filename.strip_suffix(".zip")?,
    };
    let mut images = vec![
        ("0xe000", version_dir.join(format!("{stem}.boot_app0"))),
        (
            spec.bootloader_offset,
            version_dir.join(format!("{stem}.bootloader")),
        ),
        ("0x10000", version_dir.join(format!("{stem}.bin"))),
    ];
    if console {
        images.push(("0x210000", version_dir.join("console_image.bin")));
    }
    images.push(("0x8000", version_dir.join(format!("{stem}.partitions"))));

    Some(FlashPlan {
        program: ctx.python.clone(),
        args: esp32_args(
            &version_dir.join("esptool.py"),
            spec.chip,
            &ctx.port,
            &ctx.baud_flash,
            spec.flash_size,
            &images,
        ),
    })
}

#[derive(Debug, Clone, Copy)]
struct Esp32Spec {
    chip: &'static str,
    flash_size: &'static str,
    bootloader_offset: &'static str,
    /// Version from which the console image is written; `None` means always.
    console_from: Option<f64>,
    /// Images flashed instead of the board's own below `console_from`.
    legacy_stem: Option<&'static str>,
}

fn esp32_spec(fw_filename: &str) -> Option<Esp32Spec> {
    let s3 = Esp32Spec {
        chip: "esp32s3",
        flash_size: "4MB",
        bootloader_offset: "0x0",
        console_from: None,
        legacy_stem: None,
    };
    let esp32 = Esp32Spec {
        chip: "esp32",
        flash_size: "4MB",
        bootloader_offset: "0x1000",
        console_from: Some(1.55),
        legacy_stem: None,
    };
    Some(match fw_filename {
        "rnode_firmware_t3s3.zip"
        | "rnode_firmware_t3s3_sx127x.zip"
        | "rnode_firmware_t3s3_sx1280_pa.zip"
        | "rnode_firmware_tbeam_supreme.zip"
        | "rnode_firmware_tdeck.zip" => s3,
        "rnode_firmware_xiao_esp32s3.zip" => Esp32Spec {
            flash_size: "8MB",
            ..s3
        },
        "rnode_firmware_heltec32v4pa.zip" => Esp32Spec {
            chip: "esp32-s3",
            flash_size: "16MB",
            ..s3
        },
        "rnode_firmware_heltec32v3.zip" => Esp32Spec {
            chip: "esp32-s3",
            flash_size: "8MB",
            ..s3
        },
        "rnode_firmware_heltec32v2.zip" => Esp32Spec {
            flash_size: "8MB",
            ..esp32
        },
        "rnode_firmware_tbeam_sx1262.zip" => Esp32Spec {
            legacy_stem: Some("rnode_firmware_tbeam"),
            ..esp32
        },
        "rnode_firmware_lora32v10.zip" => Esp32Spec {
            console_from: Some(1.59),
            legacy_stem: Some("rnode_firmware_lora32v20"),
            ..esp32
        },
        "rnode_firmware_lora32v21_tcxo.zip" => Esp32Spec {
            console_from: None,
            ..esp32
        },
        "rnode_firmware_tbeam.zip"
        | "rnode_firmware_lora32v20.zip"
        | "rnode_firmware_lora32v21.zip"
        | "rnode_firmware_featheresp32.zip"
        | "rnode_firmware_esp32_generic.zip"
        | "rnode_firmware_ng20.zip"
        | "rnode_firmware_ng21.zip" => esp32,
        _ => return None,
    })
}

fn esp32_args(
    flasher: &Path,
    chip: &str,
    port: &str,
    baud: &str,
    flash_size: &str,
    images: &[(&str, PathBuf)],
) -> Vec<String> {
    let mut args = vec![
        path_string(flasher),
        "--chip".to_string(),
        chip.to_string(),
        "--port".to_string(),
        port.to_string(),
        "--baud".to_string(),
        baud.to_string(),
        "--before".to_string(),
        "default_reset".to_string(),
        "--after".to_string(),
        "hard_reset".to_string(),
        "write_flash".to_string(),
        "-z".to_string(),
        "--flash_mode".to_string(),
        "dio".to_string(),
        "--flash_freq".to_string(),
        "80m".to_string(),
        "--flash_size".to_string(),
        flash_size.to_string(),
    ];
    for (offset, path) in images {
        args.push((*offset).to_string());
        args.push(path_string(path));
    }
    args
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> FlashContext {
        FlashContext {
            python: "python3".to_string(),
            port: "/dev/ttyUSB0".to_string(),
            baud_flash: "921600".to_string(),
            update_dir: PathBuf::from("/cache/update"),
            extracted_dir: PathBuf::from("/cache/extracted"),
            selected_version: "1.74".to_string(),
        }
    }

    fn update_version_file(filename: &str) -> String {
        path_string(&PathBuf::from("/cache/update").join("1.74").join(filename))
    }

    #[test]
    fn flasher_plans_match_upstream_get_flasher_call() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rnodeconf_flasher_plan/vectors.json"
        );
        let g: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let c = &g["ctx"];
        let field = |k: &str| c[k].as_str().unwrap().to_string();
        let mut mismatches = Vec::new();
        for case in g["cases"].as_array().unwrap() {
            let ctx = FlashContext {
                python: field("python"),
                port: field("port"),
                baud_flash: field("baud_flash"),
                update_dir: PathBuf::from(field("update_dir")),
                extracted_dir: PathBuf::from(field("extracted_dir")),
                selected_version: case["version"].as_str().unwrap().to_string(),
            };
            let fw = case["fw"].as_str().unwrap();
            let platform = case["platform"].as_u64().unwrap() as u8;
            let expected: Option<Vec<String>> =
                serde_json::from_value(case["argv"].clone()).unwrap();
            let got = plan_flasher(platform, fw, &ctx).map(|plan| plan.argv());
            if got != expected {
                mismatches.push(format!(
                    "{fw} @ {}\n  upstream {expected:?}\n  rust     {got:?}",
                    ctx.selected_version
                ));
            }
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    #[test]
    fn avr_plan_matches_upstream_avrdude_shape() {
        let plan = plan_flasher(model::PLATFORM_AVR, "rnode_firmware.hex", &ctx()).unwrap();
        let argv = plan.argv();
        assert_eq!(argv[0], "avrdude");
        assert!(argv.contains(&"m1284p".to_string()));
        let flash_arg = format!("flash:w:{}:i", update_version_file("rnode_firmware.hex"));
        assert!(
            argv.iter().any(|arg| arg == &flash_arg),
            "missing flash argument in {argv:?}"
        );
    }

    #[test]
    fn esp32_s3_plan_uses_full_partition_table() {
        let plan = plan_flasher(model::PLATFORM_ESP32, "rnode_firmware_t3s3.zip", &ctx()).unwrap();
        let argv = plan.argv();
        assert_eq!(argv[0], "python3");
        assert!(argv.contains(&"esp32s3".to_string()));
        assert!(argv.contains(&"0x210000".to_string()));
        let firmware_bin = update_version_file("rnode_firmware_t3s3.bin");
        assert!(
            argv.iter().any(|arg| arg == &firmware_bin),
            "missing firmware image in {argv:?}"
        );
    }

    #[test]
    fn nrf52_plan_never_invokes_hardware_in_tests() {
        let plan =
            plan_flasher(model::PLATFORM_NRF52, "rnode_firmware_rak4631.zip", &ctx()).unwrap();
        assert_eq!(
            plan.argv(),
            vec![
                "adafruit-nrfutil".to_string(),
                "dfu".to_string(),
                "serial".to_string(),
                "--package".to_string(),
                update_version_file("rnode_firmware_rak4631.zip"),
                "-p".to_string(),
                "/dev/ttyUSB0".to_string(),
                "-b".to_string(),
                "115200".to_string(),
                "-t".to_string(),
                "1200".to_string(),
            ]
        );
    }
}
