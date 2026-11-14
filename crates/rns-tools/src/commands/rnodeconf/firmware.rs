//! Firmware release lookup, download, cache and hash helpers, after
//! upstream `rnodeconf`'s `ensure_firmware_file`.

use std::fs;
use std::path::{Path, PathBuf};

use super::{log, model};

pub const DEFAULT_FIRMWARE_VERSION_URL: &str =
    "https://github.com/markqvist/rnode_firmware/releases/latest/download/release.json";
pub const FALLBACK_FIRMWARE_VERSION_URL: &str =
    "https://github.com/markqvist/rnode_firmware/releases/latest/download/release.json";
pub const FIRMWARE_UPDATE_URL: &str =
    "https://github.com/markqvist/RNode_Firmware/releases/download/";
pub const EXTRACTED_FIRMWARE: &str = "extracted_rnode_firmware.zip";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePaths {
    pub root: PathBuf,
    pub update: PathBuf,
    pub firmware: PathBuf,
    pub extracted: PathBuf,
    pub trusted_keys: PathBuf,
    pub eeprom: PathBuf,
}

impl CachePaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            update: root.join("update"),
            firmware: root.join("firmware"),
            extracted: root.join("extracted"),
            trusted_keys: root.join("trusted_keys"),
            eeprom: root.join("eeprom"),
            root,
        }
    }

    pub fn update_version_file(&self, version: &str, filename: &str) -> PathBuf {
        self.update
            .join(version)
            .join(format!("{filename}.version"))
    }
}

pub fn partition_hash(platform: u8, firmware_data: &[u8]) -> Option<[u8; 32]> {
    match platform {
        model::PLATFORM_AVR | model::PLATFORM_ESP32 => {
            let payload = firmware_data.get(..firmware_data.len().checked_sub(32)?)?;
            let embedded: [u8; 32] = firmware_data[firmware_data.len() - 32..].try_into().ok()?;
            (rns_crypto::sha::sha256(payload) == embedded).then_some(embedded)
        }
        model::PLATFORM_NRF52 => Some(rns_crypto::sha::sha256(firmware_data)),
        _ => None,
    }
}

pub fn extracted_required_files(root: &Path) -> [PathBuf; 5] {
    [
        root.join("extracted_rnode_firmware.bin"),
        root.join("extracted_rnode_firmware.boot_app0"),
        root.join("extracted_rnode_firmware.bootloader"),
        root.join("extracted_rnode_firmware.partitions"),
        root.join("extracted_console_image.bin"),
    ]
}

/// Upstream's `selected_version` and `selected_hash`.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    pub version: Option<String>,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct Source<'a> {
    pub fw_url: Option<&'a str>,
    pub nocheck: bool,
}

/// How upstream leaves a step: `graceful_exit(code)`, or an exception the
/// caller's handler logs.
enum Flow {
    Exit(u8),
    Raise(String),
}

impl From<String> for Flow {
    fn from(error: String) -> Self {
        Flow::Raise(error)
    }
}

impl From<&str> for Flow {
    fn from(error: &str) -> Self {
        Flow::Raise(error.to_string())
    }
}

/// Upstream `ensure_firmware_file`; `Err` is the `graceful_exit` code.
pub fn ensure_firmware_file(
    paths: &CachePaths,
    fw_filename: &str,
    selection: &mut Selection,
    source: Source<'_>,
) -> Result<(), u8> {
    if fw_filename == EXTRACTED_FIRMWARE {
        return ensure_extracted(paths, fw_filename, selection);
    }
    match ensure_release(paths, fw_filename, selection, source) {
        Ok(()) => Ok(()),
        Err(Flow::Exit(code)) => Err(code),
        Err(Flow::Raise(error)) => {
            log(format!(
                "An error occurred while reading version information for {fw_filename}. The contained exception was:"
            ));
            log(error);
            Err(0)
        }
    }
}

fn ensure_extracted(
    paths: &CachePaths,
    fw_filename: &str,
    selection: &mut Selection,
) -> Result<(), u8> {
    let vfpath = paths.extracted.join("extracted_rnode_firmware.version");
    if !vfpath.is_file() {
        log("No extracted firmware is available, cannot continue.");
        log(
            "Extract a firmware from an existing RNode first, using the --extract-firmware option.",
        );
        return Err(183);
    }
    if extracted_required_files(&paths.extracted)
        .iter()
        .any(|path| !path.is_file())
    {
        log("One or more required firmware files are missing from the extracted RNode");
        log("Firmware archive. Installation cannot continue. Please try extracting the");
        log("firmware again with the --extract-firmware option.");
        return Err(184);
    }
    let fields = read_release_info(&vfpath).unwrap_or_default();
    let [version, hash, ..] = fields.as_slice() else {
        log("list index out of range");
        return Err(1);
    };
    selection.version = Some(version.clone());
    selection.hash = Some(hash.clone());
    log(format!(
        "Using existing firmware file: {fw_filename} for version {version}"
    ));
    Ok(())
}

fn ensure_release(
    paths: &CachePaths,
    fw_filename: &str,
    selection: &mut Selection,
    source: Source<'_>,
) -> Result<(), Flow> {
    // Upstream creates the update directory at import.
    fs::create_dir_all(&paths.update).map_err(|e| e.to_string())?;
    if !source.nocheck {
        let latest = paths.update.join(format!("{fw_filename}.version.latest"));
        match (source.fw_url, selection.version.as_deref()) {
            (None, None) => {
                if fetch_variant(
                    DEFAULT_FIRMWARE_VERSION_URL,
                    &paths.update.join("release_info.json"),
                    fw_filename,
                    &latest,
                )
                .is_err()
                {
                    log("");
                    log("WARNING!");
                    log(
                        "Failed to retrieve latest version information for your board from the default server.",
                    );
                    log(format!(
                        "Will retry using the following fallback URL: {FALLBACK_FIRMWARE_VERSION_URL}"
                    ));
                    log("");
                    log("Hit enter if you want to proceed");
                    read_enter()?;
                    fetch_variant(
                        FALLBACK_FIRMWARE_VERSION_URL,
                        &paths.update.join("fallback_release_info.json"),
                        fw_filename,
                        &latest,
                    )
                    .inspect_err(|error| {
                        log(format!("Error while trying fallback URL: {error}"))
                    })?;
                }
            }
            (fw_url, version) => {
                let version_url = match (fw_url, version) {
                    (Some(url), None) => format!("{url}latest/download/release.json"),
                    (Some(url), Some(version)) => format!("{url}download/{version}/release.json"),
                    (None, version) => format!(
                        "{FIRMWARE_UPDATE_URL}{}/release.json",
                        version.unwrap_or_default()
                    ),
                };
                log(format!(
                    "Retrieving specified version info from {version_url}"
                ));
                if fetch_variant(
                    &version_url,
                    &paths.update.join("version_release_info.json"),
                    fw_filename,
                    &latest,
                )
                .is_err()
                {
                    log("Failed to retrive version information for your board.");
                    log("Check your internet connection and try again.");
                    log(
                        "If you don't have Internet access currently, use the --fw-version option to manually specify a version.",
                    );
                    log(
                        "You can also use --extract to copy the firmware from a known-good RNode of the same model.",
                    );
                    return Err(Flow::Exit(0));
                }
            }
        }

        let fields = read_release_info(&latest)?;
        let version = fields.first().ok_or("list index out of range")?.clone();
        if version == "not" {
            log("No valid version found for this board, exiting.");
            return Err(Flow::Exit(199));
        }
        let hash = fields.get(1).ok_or("list index out of range")?.clone();
        let version_dir = paths.update.join(&version);
        fs::create_dir_all(&version_dir).map_err(|e| e.to_string())?;
        fs::copy(&latest, paths.update_version_file(&version, fw_filename))
            .map_err(|e| e.to_string())?;
        log(format!(
            "The selected firmware for this board is version {version}"
        ));
        selection.version = Some(version);
        selection.hash = Some(hash);
    } else if selection.version.is_none() {
        log(
            "Online firmware version check was disabled, but no firmware version specified for install.",
        );
        log("use the --fw-version option to manually specify a version.");
        return Err(Flow::Exit(98));
    }

    let version = selection.version.clone().unwrap_or_default();
    let update_target_url = match source.fw_url {
        Some(url) => {
            let target = format!("{url}download/{version}/{fw_filename}");
            log(format!("Retrieving firmware from custom url {target}"));
            target
        }
        None => format!("{FIRMWARE_UPDATE_URL}{version}/{fw_filename}"),
    };
    let firmware = paths.update.join(&version).join(fw_filename);
    let fetched = fs::create_dir_all(paths.update.join(&version))
        .map_err(|e| e.to_string())
        .and_then(|()| {
            if firmware.is_file() {
                log(format!(
                    "Using existing firmware file: {fw_filename} for version {version}"
                ));
                return Ok(());
            }
            log(format!("Firmware {} not found.", firmware.display()));
            log(format!(
                "Downloading missing firmware file: {fw_filename} for version {version}"
            ));
            urlretrieve(&update_target_url, &firmware)?;
            log("Firmware file downloaded");
            Ok(())
        });
    if let Err(error) = fetched {
        log("Could not download required firmware file: ");
        log(&update_target_url);
        log("The contained exception was:");
        log(error);
        return Err(Flow::Exit(0));
    }
    match verify_firmware(paths, fw_filename, &version, selection) {
        Ok(()) => Ok(()),
        Err(Flow::Raise(error)) => {
            log(
                "An error occurred while checking firmware file integrity. The contained exception was:",
            );
            log(error);
            Err(Flow::Exit(95))
        }
        Err(exit) => Err(exit),
    }
}

fn verify_firmware(
    paths: &CachePaths,
    fw_filename: &str,
    version: &str,
    selection: &mut Selection,
) -> Result<(), Flow> {
    let version_file = paths.update_version_file(version, fw_filename);
    if selection.hash.is_none() {
        match read_release_info(&version_file) {
            Ok(fields) if fields.len() > 1 => selection.hash = Some(fields[1].clone()),
            _ => {
                log("Could not read locally cached release information.");
                log(format!(
                    "Ensure {} exists and has the correct format and hash.",
                    version_file.display()
                ));
                log("You can clear the cache with the --clear-cache option and try again.");
            }
        }
        if selection.hash.is_none() {
            log(format!(
                "No release hash found for {fw_filename}. The firmware integrity could not be verified."
            ));
            return Err(Flow::Exit(97));
        }
    }
    let selected_hash = selection.hash.clone().unwrap_or_default();
    log("Verifying firmware integrity...");
    let data = fs::read(paths.update.join(version).join(fw_filename)).map_err(|e| e.to_string())?;
    super::py_fromhex(&selected_hash).ok_or("non-hexadecimal number found in fromhex() arg")?;
    let file_hash = hex::encode(rns_crypto::sha::sha256(&data));
    if file_hash != selected_hash {
        log("");
        log(format!(
            "Firmware hash {file_hash} but should be {selected_hash}, possibly due to download corruption."
        ));
        log(
            "Firmware corrupt. Try clearing the local firmware cache with: rnodeconf --clear-cache",
        );
        return Err(Flow::Exit(96));
    }
    Ok(())
}

/// Download `url` to `path`, then record `"<version> <hash>"` of the
/// `fw_filename` entry in `latest`, as upstream does with each release.json.
fn fetch_variant(url: &str, path: &Path, fw_filename: &str, latest: &Path) -> Result<(), String> {
    urlretrieve(url, path)?;
    let data = fs::read(path).map_err(|e| e.to_string())?;
    let release: serde_json::Value = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
    let variant = release
        .get(fw_filename)
        .ok_or_else(|| format!("'{fw_filename}'"))?;
    let field = |name: &str| match variant.get(name) {
        Some(serde_json::Value::String(text)) => Ok(text.clone()),
        Some(other) => Ok(other.to_string()),
        None => Err(format!("'{name}'")),
    };
    let record = format!("{} {}", field("version")?, field("hash")?);
    fs::write(latest, record).map_err(|e| e.to_string())
}

fn read_release_info(path: &Path) -> Result<Vec<String>, String> {
    let data = fs::read(path).map_err(|e| e.to_string())?;
    let text = String::from_utf8(data).map_err(|e| e.to_string())?;
    Ok(text.split_whitespace().map(str::to_string).collect())
}

fn read_enter() -> Result<(), String> {
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) => Err("EOF when reading a line".to_string()),
        Ok(_) => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

pub const NO_FIRMWARE_SUPPORT: &str = "this rnodeconf-rs was built without the rnodeconf-firmware feature; firmware download and update are unavailable";

/// Upstream `urlretrieve`: the file is written only once the response arrived.
#[cfg(feature = "rnodeconf-firmware")]
pub fn urlretrieve(url: &str, path: &Path) -> Result<(), String> {
    use std::io::Read;
    let response = ureq::get(url).call().map_err(|e| e.to_string())?;
    let mut data = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    fs::write(path, data).map_err(|e| e.to_string())
}

#[cfg(not(feature = "rnodeconf-firmware"))]
pub fn urlretrieve(_url: &str, _path: &Path) -> Result<(), String> {
    Err(NO_FIRMWARE_SUPPORT.to_string())
}

/// Upstream `zipfile.ZipFile(archive).extractall(dir)`.
#[cfg(feature = "rnodeconf-firmware")]
pub fn extract_zip(archive: &Path, dir: &Path) -> Result<(), String> {
    let file = fs::File::open(archive).map_err(|e| e.to_string())?;
    zip::ZipArchive::new(file)
        .and_then(|mut zip| zip.extract(dir))
        .map_err(|e| e.to_string())
}

#[cfg(not(feature = "rnodeconf-firmware"))]
pub fn extract_zip(_archive: &Path, _dir: &Path) -> Result<(), String> {
    Err(NO_FIRMWARE_SUPPORT.to_string())
}

pub fn parse_sha256_hex(hex_value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_value).map_err(|e| format!("invalid SHA-256 hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 32-byte SHA-256, got {} bytes", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_paths_match_upstream_layout() {
        let paths = CachePaths::new("/tmp/rnodeconf");
        assert_eq!(paths.update, PathBuf::from("/tmp/rnodeconf/update"));
        assert_eq!(paths.firmware, PathBuf::from("/tmp/rnodeconf/firmware"));
        assert_eq!(
            paths.update_version_file("1.73", "rnode_firmware.hex"),
            PathBuf::from("/tmp/rnodeconf/update/1.73/rnode_firmware.hex.version")
        );
    }

    #[test]
    fn partition_hash_matches_upstream_platform_rules() {
        let payload = b"firmware-image";
        let hash = rns_crypto::sha::sha256(payload);
        let mut esp32 = payload.to_vec();
        esp32.extend_from_slice(&hash);
        assert_eq!(partition_hash(model::PLATFORM_ESP32, &esp32), Some(hash));

        let nrf_hash = rns_crypto::sha::sha256(&esp32);
        assert_eq!(
            partition_hash(model::PLATFORM_NRF52, &esp32),
            Some(nrf_hash)
        );

        esp32[0] ^= 1;
        assert_eq!(partition_hash(model::PLATFORM_ESP32, &esp32), None);
    }
}
