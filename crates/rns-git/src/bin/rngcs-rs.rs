//! `rngcs-rs`: the command line of `RNS/Utilities/rngit/commitsigs.py@1.6.0`.
//! git drives it as its `gpg.ssh.program`.

use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use rmpv::Value;
use rns_git::commitsigs::{
    HASH_ALGORITHM, HeaderEmail, NAMESPACE_GIT, RESERVED_EMPTY, SshSignature, armor_ssh_signature,
    create_ssh_signature, extract_commit_author, extract_commit_committer, extract_commit_tagger,
    get_pubkey_wire_format, parse_ssh_signature, unarmor_ssh_signature,
};
use rns_identity::identity::Identity;
use rns_tools::rsg::pyfmt::{py_bytes_repr, py_os_error, py_str_repr, py_utf8_error};
use rns_tools::rsg::{self, Message, Valid};

const PROG: &str = "rngcs-rs";
const HELP: &str = include_str!("../commitsigs/help.txt");
const OPERATIONS: [&str; 4] = ["sign", "find-principals", "check-novalidate", "verify"];

/// `RNS.hexrep(value, delimit=False)` for an unpacked value; `Err` is the
/// exception upstream raises.
fn hexrep_value(value: &Value) -> Result<String, String> {
    fn byte(value: &Value) -> Result<String, String> {
        match value {
            Value::Integer(i) => Ok(match i.as_i64() {
                Some(n) if n < 0 => format!("-{:x}", n.unsigned_abs()),
                _ => format!("{:02x}", i.as_u64().unwrap_or_default()),
            }),
            Value::Boolean(b) => Ok(format!("{:02x}", u8::from(*b))),
            Value::Nil => Err(
                "TypeError: unsupported format string passed to NoneType.__format__".to_string(),
            ),
            other => Err(format!(
                "ValueError: Unknown format code 'x' for object of type '{}'",
                rsg::py_type_name(other)
            )),
        }
    }
    match value {
        Value::Binary(b) => Ok(hex::encode(b)),
        Value::String(s) if s.as_str().is_some_and(|s| !s.is_empty()) => {
            Err("ValueError: Unknown format code 'x' for object of type 'str'".to_string())
        }
        Value::String(_) => Ok(String::new()),
        Value::Array(items) => items.iter().map(byte).collect(),
        Value::Map(entries) => entries.iter().map(|(k, _)| byte(k)).collect(),
        other => byte(other),
    }
}

// ---------------------------------------------------------------------------
// Command line, as upstream's argparse parser with parse_known_args
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opt {
    Help,
    Op,
    Namespace,
    Keyfile,
    Principal,
    Sigfile,
    SshOption,
}

const OPTION_STRINGS: [(&str, Opt); 8] = [
    ("-h", Opt::Help),
    ("--help", Opt::Help),
    ("-Y", Opt::Op),
    ("-n", Opt::Namespace),
    ("-f", Opt::Keyfile),
    ("-I", Opt::Principal),
    ("-s", Opt::Sigfile),
    ("-O", Opt::SshOption),
];

impl Opt {
    fn lookup(option: &str) -> Option<Opt> {
        OPTION_STRINGS
            .iter()
            .find(|(s, _)| *s == option)
            .map(|(_, o)| *o)
    }

    fn name(self) -> &'static str {
        match self {
            Opt::Help => "-h/--help",
            Opt::Op => "-Y",
            Opt::Namespace => "-n",
            Opt::Keyfile => "-f",
            Opt::Principal => "-I",
            Opt::Sigfile => "-s",
            Opt::SshOption => "-O",
        }
    }
}

#[derive(Debug, Default)]
struct Args {
    op: Option<String>,
    keyfile: Option<String>,
    principal: Option<String>,
    sigfile: Option<String>,
    file: Option<String>,
    extras: Vec<String>,
}

enum ParseExit {
    Help,
    Error(String),
}

struct OptionTuple {
    action: Option<Opt>,
    option_string: String,
    sep: Option<&'static str>,
    explicit: Option<String>,
}

fn tuple(
    action: Option<Opt>,
    option_string: &str,
    sep: Option<&'static str>,
    explicit: Option<&str>,
) -> OptionTuple {
    OptionTuple {
        action,
        option_string: option_string.to_string(),
        sep,
        explicit: explicit.map(str::to_string),
    }
}

fn partition(arg: &str) -> (&str, Option<&'static str>, Option<&str>) {
    match arg.split_once('=') {
        Some((prefix, rest)) => (prefix, Some("="), Some(rest)),
        None => (arg, None, None),
    }
}

/// `ArgumentParser._parse_optional`; `None` is a positional.
fn parse_optional(arg: &str) -> Option<Vec<OptionTuple>> {
    if !arg.starts_with('-') {
        return None;
    }
    if let Some(action) = Opt::lookup(arg) {
        return Some(vec![tuple(Some(action), arg, None, None)]);
    }
    if arg.chars().count() == 1 {
        return None;
    }
    let (prefix, sep, explicit) = partition(arg);
    if sep.is_some()
        && let Some(action) = Opt::lookup(prefix)
    {
        return Some(vec![tuple(Some(action), prefix, sep, explicit)]);
    }
    let mut result = Vec::new();
    if arg.starts_with("--") {
        for (option, action) in OPTION_STRINGS {
            if option.starts_with(prefix) {
                result.push(tuple(Some(action), option, sep, explicit));
            }
        }
    } else {
        let split = arg.char_indices().nth(2).map_or(arg.len(), |(i, _)| i);
        let (short_prefix, short_explicit) = arg.split_at(split);
        for (option, action) in OPTION_STRINGS {
            if option == short_prefix {
                result.push(tuple(Some(action), option, Some(""), Some(short_explicit)));
            } else if option.starts_with(prefix) {
                result.push(tuple(Some(action), option, sep, explicit));
            }
        }
    }
    if !result.is_empty() {
        return Some(result);
    }
    let digits = &arg[1..];
    let negative_number = (!digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()))
        || digits.split_once('.').is_some_and(|(int, frac)| {
            int.chars().all(|c| c.is_ascii_digit())
                && !frac.is_empty()
                && frac.chars().all(|c| c.is_ascii_digit())
        });
    if negative_number || arg.contains(' ') {
        return None;
    }
    Some(vec![tuple(None, arg, None, None)])
}

fn take_option(args: &mut Args, action: Opt, values: &[String]) -> Result<(), ParseExit> {
    let value = values.first().cloned();
    match action {
        Opt::Help => return Err(ParseExit::Help),
        Opt::Op => {
            let value = value.unwrap_or_default();
            if !OPERATIONS.contains(&value.as_str()) {
                return Err(ParseExit::Error(format!(
                    "argument -Y: invalid choice: {} (choose from {})",
                    py_str_repr(&value),
                    OPERATIONS.join(", ")
                )));
            }
            args.op = Some(value);
        }
        Opt::Namespace | Opt::SshOption => {}
        Opt::Keyfile => args.keyfile = value,
        Opt::Principal => args.principal = value,
        Opt::Sigfile => args.sigfile = value,
    }
    Ok(())
}

/// `ArgumentParser.parse_known_args` for upstream's parser.
fn parse_args(argv: &[String]) -> Result<Args, ParseExit> {
    let mut args = Args::default();
    let mut options: Vec<Option<Vec<OptionTuple>>> = Vec::with_capacity(argv.len());
    let mut pattern: Vec<char> = Vec::with_capacity(argv.len());
    let mut after_dashes = false;
    for arg in argv {
        if after_dashes {
            options.push(None);
            pattern.push('A');
        } else if arg == "--" {
            after_dashes = true;
            options.push(None);
            pattern.push('-');
        } else {
            let tuples = parse_optional(arg);
            pattern.push(if tuples.is_some() { 'O' } else { 'A' });
            options.push(tuples);
        }
    }
    let error = |action: Option<Opt>, message: String| {
        ParseExit::Error(match action {
            Some(action) => format!("argument {}: {message}", action.name()),
            None => message,
        })
    };
    let mut file_pending = true;
    let mut consume_positionals = |args: &mut Args, start: usize| -> usize {
        if !file_pending {
            return start;
        }
        let mut end = start;
        while pattern.get(end) == Some(&'-') {
            end += 1;
        }
        if pattern.get(end) == Some(&'A') {
            end += 1;
        }
        while pattern.get(end) == Some(&'-') {
            end += 1;
        }
        if end == start && pattern.get(end) == Some(&'O') {
            return start;
        }
        let mut values: Vec<&String> = argv[start..end].iter().collect();
        if let Some(i) = pattern[start..end].iter().position(|c| *c == '-') {
            values.remove(i);
        }
        args.file = values.first().map(|v| v.to_string());
        file_pending = false;
        end
    };

    let max_option = pattern.iter().rposition(|c| *c == 'O');
    let mut start = 0usize;
    while max_option.is_some_and(|max| start <= max) {
        let max = max_option.expect("checked");
        let mut next_option = start;
        while next_option <= max && pattern[next_option] != 'O' {
            next_option += 1;
        }
        if start != next_option {
            let end = consume_positionals(&mut args, start);
            if end > start {
                start = end;
                continue;
            }
        }
        if pattern.get(start) != Some(&'O') {
            args.extras.extend(argv[start..next_option].iter().cloned());
            start = next_option;
        }

        let tuples = options[start].as_ref().expect("an option");
        if tuples.len() > 1 {
            let matches: Vec<&str> = tuples.iter().map(|t| t.option_string.as_str()).collect();
            return Err(error(
                None,
                format!(
                    "ambiguous option: {} could match {}",
                    argv[start],
                    matches.join(", ")
                ),
            ));
        }
        let first = &tuples[0];
        let (mut action, mut option_string) = (first.action, first.option_string.clone());
        let (mut sep, mut explicit) = (first.sep, first.explicit.clone());
        let mut actions: Vec<(Opt, Vec<String>)> = Vec::new();
        let stop;
        loop {
            let Some(current) = action else {
                args.extras.push(argv[start].clone());
                stop = start + 1;
                break;
            };
            let arg_count = usize::from(current != Opt::Help);
            if let Some(value) = explicit.clone() {
                let short = !option_string[1..].starts_with('-');
                if arg_count == 0 && short && !value.is_empty() {
                    if sep == Some("=") || value.starts_with('-') {
                        return Err(error(
                            Some(current),
                            format!("ignored explicit argument {}", py_str_repr(&value)),
                        ));
                    }
                    actions.push((current, Vec::new()));
                    let mut chars = value.chars();
                    let flag = chars.next().expect("non-empty");
                    let rest = chars.as_str();
                    option_string = format!("-{flag}");
                    if let Some(next) = Opt::lookup(&option_string) {
                        action = Some(next);
                        if rest.is_empty() {
                            sep = None;
                            explicit = None;
                        } else if let Some(stripped) = rest.strip_prefix('=') {
                            sep = Some("=");
                            explicit = Some(stripped.to_string());
                        } else {
                            sep = Some("");
                            explicit = Some(rest.to_string());
                        }
                    } else {
                        args.extras.push(format!("-{value}"));
                        stop = start + 1;
                        break;
                    }
                } else if arg_count == 1 {
                    actions.push((current, vec![value]));
                    stop = start + 1;
                    break;
                } else {
                    return Err(error(
                        Some(current),
                        format!("ignored explicit argument {}", py_str_repr(&value)),
                    ));
                }
            } else {
                if arg_count == 1 && pattern.get(start + 1) != Some(&'A') {
                    return Err(error(Some(current), "expected one argument".to_string()));
                }
                actions.push((current, argv[start + 1..start + 1 + arg_count].to_vec()));
                stop = start + 1 + arg_count;
                break;
            }
        }
        for (action, values) in actions {
            take_option(&mut args, action, &values)?;
        }
        start = stop;
    }
    let stop = consume_positionals(&mut args, start);
    args.extras.extend(argv[stop..].iter().cloned());
    if args.op.is_none() {
        return Err(error(
            None,
            "the following arguments are required: -Y".to_string(),
        ));
    }
    Ok(args)
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// `RNS.Identity.from_file`, plus the Rust identity envelope rnid-rs reads.
fn load_identity(path: &str) -> Option<Identity> {
    let data = std::fs::read(path).ok()?;
    if data.len() == 64 {
        return Identity::from_private_key(&data).ok();
    }
    Identity::from_file(Path::new(path)).ok()
}

/// `open(path, "r").read()`: UTF-8 with universal newlines.
fn read_text(path: &str) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| py_os_error(&e, path))?;
    let text =
        String::from_utf8(data).map_err(|e| py_utf8_error(e.as_bytes()).unwrap_or_default())?;
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

fn read_stdin() -> Vec<u8> {
    let mut message = Vec::new();
    let _ = std::io::stdin().lock().read_to_end(&mut message);
    message
}

fn is_file(path: Option<&str>) -> bool {
    path.is_some_and(|path| !path.is_empty() && Path::new(path).is_file())
}

fn read_signature(path: &str) -> Result<SshSignature, String> {
    parse_ssh_signature(&unarmor_ssh_signature(&read_text(path)?)?)
}

fn sign(args: &Args) -> u8 {
    let keyfile = args.keyfile.as_deref();
    if !is_file(keyfile) {
        eprintln!("Identity file not found: {}", keyfile.unwrap_or("None"));
        return 1;
    }
    let Some(identity) =
        load_identity(keyfile.unwrap_or_default()).filter(Identity::has_private_key)
    else {
        eprintln!("Error: Could not load identity or identity has no private key");
        return 1;
    };
    let (message, sig_file) = match args.file.as_deref() {
        Some(file) if is_file(Some(file)) => match std::fs::read(file) {
            Ok(message) => (message, Some(format!("{file}.sig"))),
            Err(e) => {
                eprintln!("{}", py_os_error(&e, file));
                return 1;
            }
        },
        _ => (read_stdin(), None),
    };
    let rsg = match rsg::create_rsg(&identity, &message[..], false, None) {
        Ok(rsg) => rsg,
        Err(e) => {
            eprintln!("Error creating signature: {e}");
            return 1;
        }
    };
    let blob = create_ssh_signature(
        &get_pubkey_wire_format(&identity),
        NAMESPACE_GIT,
        RESERVED_EMPTY,
        HASH_ALGORITHM,
        &rsg,
    );
    let armored = armor_ssh_signature(&blob);
    match sig_file {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, &armored) {
                eprintln!("Error writing signature file: {}", py_os_error(&e, &path));
                return 1;
            }
        }
        None => {
            print!("{armored}");
            let _ = std::io::stdout().flush();
        }
    }
    0
}

fn find_principals(args: &Args) -> u8 {
    let sigfile = args.sigfile.as_deref();
    if !is_file(sigfile) {
        eprintln!("Error: Signature file not found");
        return 1;
    }
    let armored = match read_text(sigfile.unwrap_or_default()) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("Error reading signature file: {e}");
            return 1;
        }
    };
    let ssh_sig = match unarmor_ssh_signature(&armored).and_then(|raw| parse_ssh_signature(&raw)) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("Error parsing SSH signature: {e}");
            return 1;
        }
    };
    if ssh_sig.namespace != NAMESPACE_GIT {
        eprintln!(
            "Error: Namespace mismatch: {}",
            py_bytes_repr(&ssh_sig.namespace)
        );
        return 1;
    }
    let envelope = rsg::extract_signed_rsg_data(&ssh_sig.signature_data).unwrap_or(Value::Nil);
    let signer =
        match rsg::py_index(&envelope, "meta").and_then(|meta| rsg::py_index(meta, "signer")) {
            Ok(signer) => signer,
            Err(e) => {
                eprintln!("Could not determine signer identity: {e}");
                return 1;
            }
        };
    match hexrep_value(signer) {
        Ok(hex) => {
            println!("{hex}");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn check_novalidate(args: &Args) -> u8 {
    if !is_file(args.sigfile.as_deref()) {
        return 1;
    }
    match read_signature(args.sigfile.as_deref().unwrap_or_default()) {
        Ok(ssh_sig) if ssh_sig.namespace == NAMESPACE_GIT => {
            match rsg::extract_signed_rsg_data(&ssh_sig.signature_data) {
                Some(signed_data) if rsg::py_truthy(&signed_data) => 0,
                _ => 1,
            }
        }
        _ => 1,
    }
}

fn verify(args: &Args) -> u8 {
    let sigfile = args.sigfile.as_deref();
    if !is_file(sigfile) {
        eprintln!("Error: Signature file not found");
        return 1;
    }
    let message = read_stdin();
    let ssh_sig = match read_signature(sigfile.unwrap_or_default()) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("Error parsing signature: {e}");
            return 1;
        }
    };
    let mut author = extract_commit_author(&message);
    extract_commit_committer(&message);
    let Some((tagger, is_tag)) = extract_commit_tagger(&message) else {
        eprintln!("TypeError: cannot unpack non-iterable int object");
        return 1;
    };
    if ssh_sig.namespace != NAMESPACE_GIT {
        eprintln!("Invalid commit signature namespace");
        return 1;
    }
    let message_value = Value::Binary(message);
    let valid = match rsg::validate_rsg(
        &ssh_sig.signature_data,
        Message::Unpacked(&message_value),
        None,
    ) {
        Ok(valid) => valid,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let Some(Valid { signer_hash, .. }) = valid else {
        eprintln!("Invalid signature");
        return 1;
    };
    if is_tag {
        author = HeaderEmail::Email(tagger);
    }
    let signer_hash = hex::encode(signer_hash);
    if author != HeaderEmail::Email(signer_hash.clone()) {
        println!("Commit not signed by author <{author}>");
        return 1;
    }
    if let Some(principal) = args.principal.as_deref().filter(|p| !p.is_empty())
        && principal != signer_hash
    {
        eprintln!("Principal mismatch");
        return 1;
    }
    println!(
        "Good \"git\" signature for commit, signed with Reticulum Identity key <{signer_hash}>"
    );
    0
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(run(&argv))
}

fn run(argv: &[String]) -> u8 {
    let args = match parse_args(argv) {
        Ok(args) => args,
        Err(ParseExit::Help) => {
            print!("{HELP}");
            return 0;
        }
        Err(ParseExit::Error(message)) => {
            let usage = HELP.split("\n\n").next().unwrap_or_default();
            eprint!("{usage}\n{PROG}: error: {message}\n");
            return 2;
        }
    };
    if let Some(unknown) = args.extras.iter().find(|arg| !arg.starts_with("-O")) {
        eprintln!("Error: Unknown argument: {unknown}");
        return 1;
    }
    match args.op.as_deref() {
        Some("sign") => sign(&args),
        Some("find-principals") => find_principals(&args),
        Some("check-novalidate") => check_novalidate(&args),
        _ => verify(&args),
    }
}
