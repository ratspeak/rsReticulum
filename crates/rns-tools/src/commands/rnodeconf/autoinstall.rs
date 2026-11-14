//! Upstream `rnodeconf --autoinstall`: the guided installer. It picks the port,
//! board and firmware, then hands over to the key, flash and EEPROM bootstrap
//! flows by setting their options, as upstream does.

use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;
use std::sync::atomic::Ordering;

use super::firmware::{self, Selection, Source};
use super::session::RNode;
use super::{Args, ParsedEeprom, graceful_exit, log, model, open_serial, out, parse_eeprom};

const INTRO: &str = "\nHello!\n\nThis guide will help you install the RNode firmware on supported\nand homebrew devices. Please connect the device you wish to set\nup now. Hit enter when it is connected.\n";
const SELECTION_HEAD: &str = "\n---------------------------------------------------------------------------\n                               Device Selection\n";
const DETECTED: &str = "\nThe device seems to have an RNode firmware installed, but it was not\nprovisioned correctly, or it is corrupt. We are going to reinstall the\ncorrect firmware and provision it.\n";
const FRESH: &str = "\nIt looks like this is a fresh device with no RNode firmware.\n";
const DEVICE_MENU: &str = "\nWhat kind of device is this?\n\n       |   Select this option if you have an RNode of a specific\n      \\ /  type, built from a recipe or bought from a vendor.\n       '\n[1]  A specific kind of RNode\n\n       |   Select this option if you have put together an RNode\n      \\ /  of your own design, or if you are prototyping one.\n       '\n[2]  Homebrew RNode\n\n       |   Select one of these options if you want to easily turn\n      \\ /  a supported development board into an RNode.\n       '\n[3]  LilyGO LoRa32 v2.1 (aka T3 v1.6 / T3 v1.6.1)\n[4]  LilyGO LoRa32 v2.0\n[5]  LilyGO LoRa32 v1.0\n[6]  LilyGO T-Beam\n[7]  Heltec LoRa32 v2\n[8]  Heltec LoRa32 v3\n[9]  Heltec LoRa32 v4\n[10] LilyGO LoRa T3S3\n[11] RAK4631\n[12] LilyGo T-Echo\n[13] LilyGO T-Beam Supreme\n[14] LilyGO T-Deck\n[15] Heltec T114\n[16] Seeed XIAO ESP32S3 Wio-SX1262\n\n---------------------------------------------------------------------------\n\nEnter the number that matches your device type:\n? ";
const ESP32_BOARD_MENU: &str = "\nWhat kind of ESP32 board is this?\n\n[1] Adafruit Feather ESP32 (HUZZAH32)\n[2] Generic ESP32 board\n\n? ";
const NO_FIRMWARE: &str = "\nSorry, no firmware for your board currently exists.\nHelp making it a reality by contributing code or by\ndonating to the project.\n";

/// Upstream's device menu entries, by answer (1 to 16): product, whether it is
/// the T3S3 variant of the RNode product, and the notice shown before the band menu.
const DEVICES: [(u8, bool, Option<&str>); 16] = [
    (model::PRODUCT_RNODE, false, None),
    (
        model::PRODUCT_HMBRW,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                        Homebrew RNode Installer\n\nThis option allows you to install and provision the RNode firmware on a\ncustom board design, or a custom device created by coupling a generic\ndevelopment board with a supported transceiver module.\n\nImportant! Using RNode firmware on homebrew devices should currently be\nconsidered experimental. It is not intended for production or critical use.\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_T32_21,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                     LilyGO LoRa32 v2.1 RNode Installer\n\nImportant! Using RNode firmware on LoRa32 devices should currently be\nconsidered experimental. It is not intended for production or critical use.\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_T32_20,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                     LilyGO LoRa32 v2.0 RNode Installer\n\nImportant! Using RNode firmware on LoRa32 devices should currently be\nconsidered experimental. It is not intended for production or critical use.\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_T32_10,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                     LilyGO LoRa32 v1.0 RNode Installer\n\nImportant! Using RNode firmware on LoRa32 devices should currently be\nconsidered experimental. It is not intended for production or critical use.\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it.\n\nPlease Note! This device is known to have a faulty battery charging circuit,\nwhich can result in overcharging and damaging batteries. If at all possible,\nit is recommended to avoid this device.\n\nHit enter if you're sure you wish to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_TBEAM,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                          T-Beam RNode Installer\n\nThe RNode firmware can currently be installed on T-Beam devices using the\nSX1276, SX1278, SX1262 and SX1268 transceiver chips.\n\nImportant! Using RNode firmware on T-Beam devices should currently be\nconsidered experimental. It is not intended for production or critical use.\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_H32_V2,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                     Heltec LoRa32 v2.0 RNode Installer\n\nImportant! Using RNode firmware on Heltec devices should currently be\nconsidered experimental. It is not intended for production or critical use.\n\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_H32_V3,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                     Heltec LoRa32 v3.0 RNode Installer\n\nImportant! Using RNode firmware on Heltec devices should currently be\nconsidered experimental. It is not intended for production or critical use.\n\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_H32_V4,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                      Heltec LoRa32 v4 RNode Installer\n\nImportant! Using RNode firmware on Heltec devices should currently be\nconsidered experimental. It is not intended for production or critical use.\n\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_RNODE,
        true,
        Some(
            "\n---------------------------------------------------------------------------\n                     LilyGO LoRa32 T3S3 RNode Installer\n\nImportant! Using RNode firmware on T3S3 devices should currently be\nconsidered experimental. It is not intended for production or critical use.\n\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_RAK4631,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                     RAK4631 RNode Installer\n\nImportant! Using RNode firmware on RAKwireless devices should currently be\nconsidered experimental. It is not intended for production or critical use.\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_TECHO,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                     LilyGo T-Echo RNode Installer\n\nImportant! Using RNode firmware on LilyGo T-Echo devices should currently be\nconsidered experimental. It is not intended for production or critical use.\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_TBEAM_S_V1,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                       T-Beam Supreme RNode Installer\n\nThe RNode firmware can currently be installed on T-Beam Supreme devices\nusing the SX1262 and SX1268 transceiver chips.\n\nImportant! Using RNode firmware on T-Beam devices should currently be\nconsidered experimental. It is not intended for production or critical use.\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_TDECK,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                            T-Deck RNode Installer\n\nThe RNode firmware can currently be installed on T-Deck devices using the\nSX1262 and SX1268 transceiver chips.\n\nImportant! Using RNode firmware on T-Beam devices should currently be\nconsidered experimental. It is not intended for production or critical use.\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_HELTEC_T114,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                      Heltec T114 RNode Installer\n\nImportant! Using RNode firmware on Heltec T114 devices should currently be\nconsidered experimental. It is not intended for production or critical use.\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
    (
        model::PRODUCT_XIAO_S3,
        false,
        Some(
            "\n---------------------------------------------------------------------------\n                 SeeedStudio XIAO esp32s3 wio RNode Installer\n\nImportant! Using RNode firmware on SeeedStudio XIAO/wio devices should currently be\nconsidered experimental. It is not intended for production or critical use.\nThe currently supplied firmware is provided AS-IS as a courtesy to those\nwho would like to experiment with it. Hit enter to continue.\n---------------------------------------------------------------------------\n",
        ),
    ),
];

const MENU_HMBRW_0: (&str, &str) = (
    "\nWhat kind of microcontroller is your board based on?\n\n[1] AVR ATmega1284P\n[2] AVR ATmega2560\n[3] Espressif Systems ESP32\n\n? ",
    "That MCU type does not exist, exiting now.\n",
);
const MENU_HMBRW_1: (&str, &str) = (
    "\nWhat transceiver module does your board use?\n\n[1] SX1276/SX1278 with antenna port on PA_BOOST pin\n[2] SX1276/SX1278 with antenna port on RFO pin\n\n? ",
    "That transceiver type does not exist, exiting now.\n",
);
const MENU_RNODE_0: (&str, &str) = (
    "\nWhat model is this RNode?\n\n[1] Handheld v2.1 RNode, 410 - 525 MHz\n[2] Handheld v2.1 RNode, 820 - 1020 MHz\n\n[3] Original v1.x RNode, 410 - 525 MHz\n[4] Original v1.x RNode, 820 - 1020 MHz\n\n[5] Prototype v2.2 RNode, 410 - 525 MHz\n[6] Prototype v2.2 RNode, 820 - 1020 MHz\n\n? ",
    "That model does not exist, exiting now.\n",
);
const MENU_RNODE_1: (&str, &str) = (
    "\nWhat band is this T3S3 for?\n\n[1] 433 MHz         (with SX1278 chip)\n[2] 868/915/923 MHz (with SX1276 chip)\n\n[3] 433 MHz         (with SX1268 chip)\n[4] 868/915/923 MHz (with SX1262 chip)\n\n[5] 2.4 GHz         (with SX1280 chip and PA)\n\n? ",
    "That model does not exist, exiting now.\n",
);
const MENU_TBEAM_0: (&str, &str) = (
    "\nWhat band is this T-Beam for?\n\n[1] 433 MHz         (with SX1278 chip)\n[2] 868/915/923 MHz (with SX1276 chip)\n\n[3] 433 MHz         (with SX1268 chip)\n[4] 868/915/923 MHz (with SX1262 chip)\n\n? ",
    "That band does not exist, exiting now.\n",
);
const MENU_TBEAM_S_V1_0: (&str, &str) = (
    "\nWhat band is this T-Beam Supreme for?\n\n[1] 433 MHz         (with SX1268 chip)\n[2] 868/915/923 MHz (with SX1262 chip)\n\n? ",
    "That band does not exist, exiting now.\n",
);
const MENU_TDECK_0: (&str, &str) = (
    "\nWhat band is this T-Deck for?\n\n[1] 433 MHz         (with SX1268 chip)\n[2] 868/915/923 MHz (with SX1262 chip)\n\n? ",
    "That band does not exist, exiting now.\n",
);
const MENU_T32_10_0: (&str, &str) = (
    "\nWhat band is this LoRa32 for?\n\n[1] 433 MHz\n[2] 868 MHz\n[3] 915 MHz\n[4] 923 MHz\n\n? ",
    "That band does not exist, exiting now.\n",
);
const MENU_T32_20_0: (&str, &str) = (
    "\nWhat band is this LoRa32 for?\n\n[1] 433 MHz\n[2] 868 MHz\n[3] 915 MHz\n[4] 923 MHz\n\n? ",
    "That band does not exist, exiting now.\n",
);
const MENU_T32_21_0: (&str, &str) = (
    "\nWhat band is this LoRa32 for?\n\n[1] 433 MHz\n[2] 868/915/923 MHz\n[3] 433 MHz, with TCXO\n[4] 868/915/923 MHz, with TCXO\n\n? ",
    "That band does not exist, exiting now.\n",
);
const MENU_H32_V2_0: (&str, &str) = (
    "\nWhat band is this Heltec LoRa32 V2 for?\n\n[1] 433 MHz\n[2] 868 MHz\n[3] 915 MHz\n[4] 923 MHz\n\n? ",
    "That band does not exist, exiting now.\n",
);
const MENU_H32_V3_0: (&str, &str) = (
    "\nWhat band is this Heltec LoRa32 V3 for?\n\n[1] 433 MHz\n[2] 868 MHz\n[3] 915 MHz\n[4] 923 MHz\n\n? ",
    "That band does not exist, exiting now.\n",
);
const MENU_H32_V4_0: (&str, &str) = (
    "\nWhat band is this Heltec LoRa32 V4 for?\n\n[1] 868 MHz (28 dBm output)\n[2] 915 MHz (28 dBm output)\n[3] 923 MHz (28 dBm output)\n\n? ",
    "That band does not exist, exiting now.\n",
);
const MENU_HELTEC_T114_0: (&str, &str) = (
    "\nWhat band is this Heltec T114 for?\n\n[1] 433 MHz\n[2] 868 MHz\n[3] 915 MHz\n[4] 923 MHz\n\n? ",
    "That band does not exist, exiting now.\n",
);
const MENU_XIAO_S3_0: (&str, &str) = (
    "\nWhat band is this XIAO esp32s3 wio module for?\n\n[1] 433 MHz\n[2] 868 MHz\n\n? ",
    "That band does not exist, exiting now.\n",
);
const MENU_RAK4631_0: (&str, &str) = (
    "\nWhat band is this RAK4631 for?\n\n[1] 433 MHz\n[2] 868 MHz\n[3] 915 MHz\n[4] 923 MHz\n\n? ",
    "That band does not exist, exiting now.\n",
);
const MENU_TECHO_0: (&str, &str) = (
    "\nWhat band is this T-Echo for?\n\n[1] 433 MHz\n[2] 868 MHz\n[3] 915 MHz\n[4] 923 MHz\n\n? ",
    "That band does not exist, exiting now.\n",
);

/// Upstream's selected product, model, platform, MCU and firmware file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub product: u8,
    pub model: u8,
    pub platform: u8,
    pub mcu: u8,
    pub fw_filename: String,
}

/// What the installer shows before reading a line.
pub enum Prompt<'a> {
    /// A notice that waits for Enter.
    Notice(&'a str),
    /// A numbered menu ending in its "? " prompt.
    Menu(&'a str),
}

/// How the installer ends before the confirmation.
#[derive(Debug, PartialEq, Eq)]
pub enum Stop {
    /// Upstream prints this line and exits 0.
    Message(&'static str),
    /// No firmware exists for the selection.
    NoFirmware,
}

/// Python `int()` on an input line.
fn int(line: Option<String>) -> Option<i64> {
    let line = line?;
    let text = line.trim();
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    text.replace('_', "").parse().ok()
}

/// Upstream's menus from the device type to the firmware file. `ask` shows a
/// prompt and returns the line read, `None` at end of input.
pub fn choose(
    detected: bool,
    ask: &mut dyn FnMut(Prompt) -> Option<String>,
) -> Result<Choice, Stop> {
    let menu = format!(
        "{SELECTION_HEAD}{}{DEVICE_MENU}",
        if detected { DETECTED } else { FRESH }
    );
    let no_device = Stop::Message("That device type does not exist, exiting now.");
    let c_dev = int(ask(Prompt::Menu(&menu))).filter(|c| (1..=16).contains(c));
    let Some(c_dev) = c_dev else {
        return Err(no_device);
    };
    let (product, t3s3, notice) = DEVICES[c_dev as usize - 1];
    if let Some(notice) = notice
        && ask(Prompt::Notice(notice)).is_none()
    {
        return Err(no_device);
    }

    // (menu, last valid answer, answer -> (model, platform, mcu))
    let pick = |menu: (&'static str, &'static str),
                top: i64,
                ask: &mut dyn FnMut(Prompt) -> Option<String>| {
        int(ask(Prompt::Menu(menu.0)))
            .filter(|c| (1..=top).contains(c))
            .ok_or(Stop::Message(menu.1.trim_end()))
    };
    use model::{MCU_1284P as P1284, MCU_2560 as M2560, MCU_ESP32 as ESP, MCU_NRF52 as NRF};
    use model::{PLATFORM_AVR as AVR, PLATFORM_ESP32 as PESP, PLATFORM_NRF52 as PNRF};
    let (model, platform, mcu) = match product {
        model::PRODUCT_HMBRW => {
            let (mcu, platform) = match pick(MENU_HMBRW_0, 3, ask)? {
                1 => (P1284, AVR),
                2 => (M2560, AVR),
                _ => (ESP, PESP),
            };
            // Upstream accepts a third transceiver answer that changes nothing.
            let model = match pick(MENU_HMBRW_1, 3, ask)? {
                1 => 0xFE,
                _ => 0xFF,
            };
            (model, platform, mcu)
        }
        model::PRODUCT_RNODE if !t3s3 => match pick(MENU_RNODE_0, 6, ask)? {
            1 => (0xA2, PESP, ESP),
            2 => (0xA7, PESP, ESP),
            3 => (0xA4, AVR, P1284),
            4 => (0xA9, AVR, P1284),
            5 => (0xA1, PESP, ESP),
            _ => (0xA6, PESP, ESP),
        },
        model::PRODUCT_RNODE => {
            let model = [0xA5, 0xAA, 0xA1, 0xA6, 0xAC][pick(MENU_RNODE_1, 5, ask)? as usize - 1];
            (model, PESP, ESP)
        }
        _ => {
            let (menu, top, platform, mcu, models): (_, _, _, _, &[u8]) = match product {
                model::PRODUCT_TBEAM => (MENU_TBEAM_0, 4, PESP, ESP, &[0xE4, 0xE9, 0xE3, 0xE8]),
                model::PRODUCT_TBEAM_S_V1 => (MENU_TBEAM_S_V1_0, 2, PESP, ESP, &[0xDB, 0xDC]),
                model::PRODUCT_TDECK => (MENU_TDECK_0, 2, PESP, ESP, &[0xD4, 0xD9]),
                model::PRODUCT_T32_10 => (MENU_T32_10_0, 4, PESP, ESP, &[0xBA, 0xBB, 0xBB, 0xBB]),
                model::PRODUCT_T32_20 => (MENU_T32_20_0, 4, PESP, ESP, &[0xB3, 0xB8, 0xB8, 0xB8]),
                model::PRODUCT_T32_21 => (
                    MENU_T32_21_0,
                    4,
                    PESP,
                    ESP,
                    &[0xB4, 0xB9, model::MODEL_B4_TCXO, model::MODEL_B9_TCXO],
                ),
                model::PRODUCT_H32_V2 => (MENU_H32_V2_0, 4, PESP, ESP, &[0xC4, 0xC9, 0xC9, 0xC9]),
                model::PRODUCT_H32_V3 => (MENU_H32_V3_0, 4, PESP, ESP, &[0xC5, 0xCA, 0xCA, 0xCA]),
                model::PRODUCT_H32_V4 => (MENU_H32_V4_0, 3, PESP, ESP, &[0xC8, 0xC8, 0xC8]),
                model::PRODUCT_HELTEC_T114 => {
                    (MENU_HELTEC_T114_0, 4, PNRF, NRF, &[0xC6, 0xC7, 0xC7, 0xC7])
                }
                model::PRODUCT_XIAO_S3 => (MENU_XIAO_S3_0, 2, PESP, ESP, &[0xDE, 0xDD]),
                model::PRODUCT_RAK4631 => (MENU_RAK4631_0, 4, PNRF, NRF, &[0x11, 0x12, 0x12, 0x12]),
                _ => (MENU_TECHO_0, 4, PNRF, NRF, &[0x16, 0x17, 0x17, 0x17]),
            };
            (models[pick(menu, top, ask)? as usize - 1], platform, mcu)
        }
    };

    let fw_filename = if model != 0xFF && model != 0xFE {
        model::model_info(model).and_then(|info| info.firmware_filename)
    } else if platform == AVR {
        Some(if mcu == P1284 {
            "rnode_firmware.hex"
        } else {
            "rnode_firmware_m2560.hex"
        })
    } else {
        match int(ask(Prompt::Menu(ESP32_BOARD_MENU))) {
            Some(1) => Some("rnode_firmware_featheresp32.zip"),
            Some(2) => Some("rnode_firmware_esp32_generic.zip"),
            _ => {
                return Err(Stop::Message(
                    "That ESP32 board does not exist, exiting now.",
                ));
            }
        }
    };
    let fw_filename = fw_filename.ok_or(Stop::NoFirmware)?;
    Ok(Choice {
        product,
        model,
        platform,
        mcu,
        fw_filename: fw_filename.to_string(),
    })
}

/// What the installer decided, for the flash and bootstrap steps after it.
pub struct Plan {
    pub choice: Choice,
    pub version: String,
}

impl Plan {
    /// Upstream's `wants_fw_provision` after a successful flash.
    pub fn provisions_firmware_hash(&self) -> bool {
        let extracted = self.choice.fw_filename == firmware::EXTRACTED_FIRMWARE;
        self.choice.platform == model::PLATFORM_ESP32
            || (self.choice.platform == model::PLATFORM_NRF52 && !extracted)
    }
}

/// Upstream `clear()`: `os.system('clear')`, which only draws on a terminal.
fn clear() {
    let mut stdout = std::io::stdout().lock();
    if stdout.is_terminal() {
        let _ = write!(stdout, "\x1b[H\x1b[2J\x1b[3J");
        let _ = stdout.flush();
    }
}

fn show(text: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = write!(stdout, "{text}");
    let _ = stdout.flush();
}

/// One `input()` line without its newline; `None` at end of input.
fn read_line() -> Option<String> {
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim_end_matches(['\n', '\r']).to_string()),
    }
}

fn describe(port: &serialport::SerialPortInfo) -> (String, String) {
    match &port.port_type {
        serialport::SerialPortType::UsbPort(info) => (
            info.product.clone().unwrap_or_else(|| "None".to_string()),
            info.serial_number
                .clone()
                .unwrap_or_else(|| "None".to_string()),
        ),
        _ => ("None".to_string(), "None".to_string()),
    }
}

/// Upstream's `args.autoinstall` block. On success the options are set for
/// the key, flash and bootstrap steps; `Err` is upstream's exit.
pub fn run(args: &mut Args) -> Result<Plan, ExitCode> {
    clear();
    if args.port.is_none() {
        show(INTRO);
        if read_line().is_none() {
            eprintln!("rnodeconf-rs: EOF when reading a line");
            return Err(ExitCode::from(1));
        }
    }
    super::QUIET_UNVERIFIED.store(true, Ordering::Relaxed);

    let ports = serialport::available_ports().unwrap_or_default();
    let (port_path, serial) = match args.port.clone() {
        None => {
            let listed: Vec<_> = ports.iter().rev().collect();
            out("Detected serial ports:");
            for (i, port) in listed.iter().enumerate() {
                let (product, serial) = describe(port);
                out(format!(
                    "  [{}] {} ({product}, {serial})",
                    i + 1,
                    port.port_name
                ));
            }
            show("\nEnter the number of the serial port your device is connected to:\n? ");
            let chosen = int(read_line())
                .filter(|c| *c >= 1 && *c as usize <= listed.len())
                .map(|c| listed[c as usize - 1]);
            let Some(port) = chosen else {
                out("That port does not exist, exiting now.");
                return Err(ExitCode::SUCCESS);
            };
            let (product, serial) = describe(port);
            clear();
            out(format!(
                "\nOk, using device on {} ({product}, {serial})",
                port.port_name
            ));
            (port.port_name.clone(), (serial != "None").then_some(serial))
        }
        Some(path) => {
            let Some(port) = ports.iter().find(|port| port.port_name == path) else {
                out(format!("Could not find specified port {path}, exiting now"));
                return Err(ExitCode::SUCCESS);
            };
            let (_, serial) = describe(port);
            out(format!("\nUsing device on {path}"));
            (path, (serial != "None").then_some(serial))
        }
    };

    out("\nProbing device...");
    let port = match open_serial(&port_path) {
        Ok(port) => port,
        Err(error) => {
            log("Could not open the specified serial port. The contained exception was:");
            log(error.to_string());
            return Err(ExitCode::SUCCESS);
        }
    };
    let mut rnode = RNode::new(port, port_path.clone());
    rnode.usb_serial_id = serial;
    if rnode.device_probe().is_err() {
        log("No answer from device");
    }
    let detected = rnode.detected == Some(true);
    if detected {
        log("Trying to read EEPROM...");
        if rnode.download_eeprom().is_err() {
            return Err(graceful_exit(&mut rnode, 1));
        }
    }
    let provisioned_and_signed = rnode.eeprom.as_deref().is_some_and(|image| {
        matches!(parse_eeprom(image, &rnode.name), ParsedEeprom::Device(Some(device)) if device.signature.valid)
    });
    if provisioned_and_signed {
        out("\nThis device is already installed and provisioned. No further action will");
        out("be taken. If you wish to completely reinstall this device, you must first");
        out("wipe the current EEPROM. See the help for more info.\n\nExiting now.");
        return Err(graceful_exit(&mut rnode, 0));
    }

    let mut ask = |prompt: Prompt| {
        match prompt {
            Prompt::Notice(text) => {
                clear();
                show(text);
            }
            Prompt::Menu(text) => show(text),
        }
        read_line()
    };
    let mut choice = match choose(detected, &mut ask) {
        Ok(choice) => choice,
        Err(Stop::Message(line)) => {
            out(line);
            return Err(graceful_exit(&mut rnode, 0));
        }
        Err(Stop::NoFirmware) => {
            show(NO_FIRMWARE);
            out("");
            super::print_donation_block();
            out("");
            return Err(graceful_exit(&mut rnode, 0));
        }
    };
    if args.use_extracted {
        choice.fw_filename = firmware::EXTRACTED_FIRMWARE.to_string();
    }

    clear();
    let band = model::model_info(choice.model).map_or("", |info| info.band);
    out("");
    out("------------------------------------------------------------------------------");
    out("                               Installer Ready");
    out("");
    out("Ok, that should be all the information we need. Please confirm the following");
    out("summary before proceeding. In the next step, the device will be flashed and");
    out("provisioned, so make sure that you are satisfied with your choices.\n");
    out(format!("Serial port     : {port_path}"));
    out(format!(
        "Device type     : {} {band}",
        model::product_name(choice.product).unwrap_or_default()
    ));
    out(format!(
        "Platform        : {}",
        model::platform_name(choice.platform).unwrap_or_default()
    ));
    out(format!(
        "Device MCU      : {}",
        model::mcu_name(choice.mcu).unwrap_or_default()
    ));
    out(format!("Firmware file   : {}", choice.fw_filename));
    out("");
    out("------------------------------------------------------------------------------");
    show("\nIs the above correct? [y/N] ");
    if read_line().map(|line| line.to_lowercase()).as_deref() != Some("y") {
        out("OK, aborting now.");
        return Err(graceful_exit(&mut rnode, 0));
    }

    args.key = true;
    args.port = Some(port_path);
    args.hwrev = Some(1);
    args.update = false;
    args.flash = true;

    log("Checking firmware file availability...");
    let paths = match super::rnodeconf_cache_paths() {
        Ok(paths) => paths,
        Err(error) => {
            log("Could not obain firmware package for your board");
            log(format!("The contained exception was: {error}"));
            return Err(graceful_exit(&mut rnode, 0));
        }
    };
    let mut selection = Selection {
        version: args.fw_version.clone(),
        hash: None,
    };
    let source = Source {
        fw_url: args.fw_url.as_deref(),
        nocheck: args.nocheck,
    };
    if let Err(code) =
        firmware::ensure_firmware_file(&paths, &choice.fw_filename, &mut selection, source)
    {
        return Err(graceful_exit(&mut rnode, code));
    }
    rnode.close();
    Ok(Plan {
        choice,
        version: selection.version.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every menu path upstream's own installer takes (fixture made by its
    /// generator from rnodeconf 2.5.0) selects the same board and firmware here.
    #[test]
    fn menu_answers_select_what_upstream_selects() {
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/rnodeconf_autoinstall/choices.json"
        ))
        .unwrap();
        for case in golden["cases"].as_array().unwrap() {
            let mut answers = case["answers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap().to_string())
                .collect::<Vec<_>>()
                .into_iter();
            let result = choose(false, &mut |_| answers.next());
            let label = &case["answers"];
            match case["stop"].as_str() {
                Some(line) => match result {
                    Err(Stop::Message(got)) => assert_eq!(got, line, "{label}"),
                    other => panic!("{label}: expected exit {line:?}, got {other:?}"),
                },
                None => {
                    let choice = result.unwrap_or_else(|stop| panic!("{label}: {stop:?}"));
                    let expected = Choice {
                        product: case["product"].as_u64().unwrap() as u8,
                        model: case["model"].as_u64().unwrap() as u8,
                        platform: case["platform"].as_u64().unwrap() as u8,
                        mcu: case["mcu"].as_u64().unwrap() as u8,
                        fw_filename: case["fw_filename"].as_str().unwrap().to_string(),
                    };
                    assert_eq!(choice, expected, "{label}");
                }
            }
        }
    }
}
