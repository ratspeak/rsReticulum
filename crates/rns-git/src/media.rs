//! WebP conversion through external encoders (`RNS/Utilities/rngit/media.py@1.6.0`).

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// `CONVERSION_TIMEOUT`: one deadline across the input and encoder processes.
pub const CONVERSION_TIMEOUT: Duration = Duration::from_secs(8);

/// `BACKENDS`, in preference order.
pub const BACKENDS: [(&str, &[&str]); 5] = [
    ("magick", &["magick", "-", "webp:-"]),
    ("convert", &["convert", "-", "webp:-"]),
    ("gm", &["gm", "convert", "-", "webp:-"]),
    (
        "ffmpeg",
        &[
            "ffmpeg",
            "-y",
            "-loglevel",
            "error",
            "-i",
            "-",
            "-f",
            "webp",
            "pipe:1",
        ],
    ),
    (
        "avconv",
        &[
            "avconv",
            "-y",
            "-loglevel",
            "error",
            "-i",
            "-",
            "-f",
            "webp",
            "pipe:1",
        ],
    ),
];

/// The encoder argv for a source of this extension, with the input format
/// named. Upstream lets the encoder guess the format from the content, so a
/// file with an image name could be read as SVG, PostScript or a playlist;
/// here only the decoder for the extension runs.
pub fn encoder_argv(backend_argv: &[&str], source_ext: &str) -> Option<Vec<String>> {
    let (coder, demuxer) = match source_ext.to_ascii_lowercase().as_str() {
        ".png" => ("png", "png_pipe"),
        ".jpg" | ".jpeg" => ("jpeg", "jpeg_pipe"),
        ".gif" => ("gif", "gif"),
        ".tiff" | ".tif" => ("tiff", "tiff_pipe"),
        ".bmp" => ("bmp", "bmp_pipe"),
        _ => return None,
    };
    let mut argv = Vec::with_capacity(backend_argv.len() + 2);
    for arg in backend_argv {
        match (backend_argv[0], *arg) {
            ("ffmpeg" | "avconv", "-i") => {
                argv.extend(["-f".to_string(), demuxer.to_string(), "-i".to_string()])
            }
            ("magick" | "convert" | "gm", "-") => argv.push(format!("{coder}:-")),
            _ => argv.push(arg.to_string()),
        }
    }
    Some(argv)
}

/// `_ENV_BACKEND`, read once as upstream reads it at import.
fn env_backend() -> Option<&'static str> {
    static ENV: OnceLock<Option<String>> = OnceLock::new();
    ENV.get_or_init(|| {
        std::env::var("RNGIT_MEDIA_BACKEND")
            .ok()
            .filter(|v| !v.is_empty())
    })
    .as_deref()
}

static WINNER: Mutex<Option<&'static str>> = Mutex::new(None);
static NO_BACKEND_LOGGED: Mutex<bool> = Mutex::new(false);

/// `shutil.which`: an executable file of that name on `PATH`.
#[cfg(unix)]
pub fn which(tool: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        std::fs::metadata(dir.join(tool))
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    })
}

/// `shutil.which` on Windows: a file of that name on `PATH`, tried with each
/// `PATHEXT` extension unless it already ends in one.
#[cfg(not(unix))]
pub fn which(tool: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
    let extensions: Vec<&str> = pathext.split(';').filter(|e| !e.is_empty()).collect();
    let lower = tool.to_ascii_lowercase();
    let names: Vec<String> = if extensions
        .iter()
        .any(|e| lower.ends_with(&e.to_ascii_lowercase()))
    {
        vec![tool.to_string()]
    } else {
        extensions.iter().map(|e| format!("{tool}{e}")).collect()
    };
    std::env::split_paths(&path).any(|dir| names.iter().any(|name| dir.join(name).is_file()))
}

/// `_selected_backend` for a forced name, a tool lookup and the previous
/// winner. A forced name whose tool is absent selects nothing.
pub fn select_backend(
    forced: Option<&str>,
    present: &dyn Fn(&str) -> bool,
    winner: Option<&str>,
) -> Option<(&'static str, &'static [&'static str])> {
    if let Some(forced) = forced {
        return BACKENDS
            .iter()
            .find(|(name, argv)| *name == forced && present(argv[0]))
            .copied();
    }
    let mut order: Vec<_> = BACKENDS.to_vec();
    if let Some(winner) = winner {
        order.sort_by_key(|(name, _)| *name != winner);
    }
    order.into_iter().find(|(_, argv)| present(argv[0]))
}

/// `_configured_backend` without quality or size options, as the page node calls it.
fn configured_backend() -> Option<(&'static str, &'static [&'static str])> {
    let mut winner = WINNER.lock().unwrap_or_else(|e| e.into_inner());
    let selected = select_backend(env_backend(), &which, *winner);
    let mut logged = NO_BACKEND_LOGGED.lock().unwrap_or_else(|e| e.into_inner());
    match selected {
        None => {
            if !*logged {
                *logged = true;
                tracing::warn!(
                    "No WebP encoding backend available for media conversion. You can Install ImageMagick or ffmpeg to enable image conversion."
                );
            }
            None
        }
        Some(backend) => {
            if env_backend().is_none() {
                *winner = Some(backend.0);
            }
            *logged = false;
            Some(backend)
        }
    }
}

/// `_webp_info`: the image size from a WebP header of at least 30 bytes.
pub fn webp_info(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() < 30 || &data[..4] != b"RIFF" || &data[8..12] != b"WEBP" {
        return None;
    }
    let le = |b: &[u8]| {
        b.iter()
            .rev()
            .fold(0u32, |acc, &x| (acc << 8) | u32::from(x))
    };
    let (width, height) = match &data[12..16] {
        b"VP8X" => (le(&data[24..27]) + 1, le(&data[27..30]) + 1),
        b"VP8 " => (le(&data[26..28]) & 0x3FFF, le(&data[28..30]) & 0x3FFF),
        b"VP8L" => {
            let bits = le(&data[21..25]);
            ((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1)
        }
        _ => return None,
    };
    (width > 0 && height > 0).then_some((width, height))
}

fn valid_webp(path: &Path) -> bool {
    let mut header = Vec::with_capacity(30);
    std::fs::File::open(path)
        .and_then(|f| f.take(30).read_to_end(&mut header))
        .is_ok_and(|_| webp_info(&header).is_some())
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn stderr_tail(child: &mut Child) -> String {
    let mut data = Vec::new();
    if let Some(stderr) = child.stderr.take() {
        let _ = stderr.take(1024).read_to_end(&mut data);
    }
    String::from_utf8_lossy(&data).trim().to_string()
}

/// `convert_to_webp`: `input_argv` writes the source image to stdout and the
/// encoder writes WebP to `output_path`. Both run by argv, never through a shell.
pub fn convert_to_webp(
    input_argv: &[&str],
    output_path: &Path,
    cwd: Option<&Path>,
    source_ext: &str,
) -> bool {
    let Some((backend, backend_argv)) = configured_backend() else {
        return false;
    };
    let Some(encoder_argv) = encoder_argv(backend_argv, source_ext) else {
        return false;
    };
    let result = (|| -> std::io::Result<bool> {
        let output = std::fs::File::create(output_path)?;
        let mut input_cmd = Command::new(input_argv[0]);
        input_cmd
            .args(&input_argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(cwd) = cwd {
            input_cmd.current_dir(cwd);
        }
        let mut input = input_cmd.spawn()?;
        let pipe = input.stdout.take().expect("piped stdout");
        let encoder = Command::new(&encoder_argv[0])
            .args(&encoder_argv[1..])
            .stdin(pipe)
            .stdout(output)
            .stderr(Stdio::piped())
            .spawn();
        let mut encoder = match encoder {
            Ok(child) => child,
            Err(e) => {
                terminate(&mut input);
                return Err(e);
            }
        };
        let deadline = Instant::now() + CONVERSION_TIMEOUT;
        let mut encoder_status = None;
        let mut input_done = false;
        loop {
            if encoder_status.is_none() {
                encoder_status = encoder.try_wait()?;
            }
            if encoder_status.is_some() && !input_done {
                input_done = input.try_wait()?.is_some();
            }
            if encoder_status.is_some() && input_done {
                break;
            }
            if Instant::now() >= deadline {
                terminate(&mut input);
                terminate(&mut encoder);
                tracing::warn!(
                    "Media conversion via {backend} timed out after {} seconds",
                    CONVERSION_TIMEOUT.as_secs()
                );
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if !encoder_status.is_some_and(|s| s.success()) {
            let mut detail = String::new();
            let encoder_tail = stderr_tail(&mut encoder);
            let input_tail = stderr_tail(&mut input);
            if !encoder_tail.is_empty() {
                detail.push_str(&format!(" Encoder: {encoder_tail}"));
            }
            if !input_tail.is_empty() {
                detail.push_str(&format!(" Input: {input_tail}"));
            }
            tracing::warn!("Media conversion via {backend} failed.{detail}");
            return Ok(false);
        }
        if !valid_webp(output_path) {
            tracing::warn!("Media conversion via {backend} produced invalid WebP output");
            return Ok(false);
        }
        tracing::debug!("Media converted to WebP with {backend}");
        Ok(true)
    })();
    result.unwrap_or_else(|e| {
        tracing::warn!("Error during media conversion: {e}");
        false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_is_told_the_input_format() {
        let argv = |backend: &str, ext: &str| {
            let (_, base) = BACKENDS.iter().find(|(name, _)| *name == backend).unwrap();
            encoder_argv(base, ext).map(|a| a.join(" "))
        };
        assert_eq!(argv("magick", ".PNG").unwrap(), "magick png:- webp:-");
        assert_eq!(argv("convert", ".jpg").unwrap(), "convert jpeg:- webp:-");
        assert_eq!(argv("gm", ".tif").unwrap(), "gm convert tiff:- webp:-");
        assert_eq!(
            argv("ffmpeg", ".gif").unwrap(),
            "ffmpeg -y -loglevel error -f gif -i - -f webp pipe:1"
        );
        assert_eq!(
            argv("avconv", ".bmp").unwrap(),
            "avconv -y -loglevel error -f bmp_pipe -i - -f webp pipe:1"
        );
        // No decoder is named for anything else, so nothing is converted.
        assert_eq!(argv("magick", ".svg"), None);
        assert_eq!(argv("ffmpeg", ".webp"), None);
    }
}
