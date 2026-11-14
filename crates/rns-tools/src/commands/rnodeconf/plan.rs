//! Operations this build refuses, checked where upstream `rnodeconf` would
//! start them: before the port check for portless flows, after it otherwise.

use super::Args;

/// Flows upstream runs without a serial port.
pub fn refusal_without_port(args: &Args) -> Option<String> {
    if args.extract {
        return Some("firmware extraction is not implemented yet".to_string());
    }
    if args.autoinstall {
        return Some("firmware flashing is not implemented yet".to_string());
    }
    None
}

/// Flows upstream starts only once a port is given.
pub fn refusal_with_port(args: &Args) -> Option<String> {
    if args.flash || args.update {
        return Some("firmware flashing is not implemented yet".to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn args(list: &[&str]) -> Args {
        Args::parse_from(std::iter::once("rnodeconf").chain(list.iter().copied()))
    }

    #[test]
    fn firmware_flows_are_refused_only_once_a_port_is_given() {
        for list in [&["--flash", "p"][..], &["--update", "p"][..]] {
            assert!(refusal_without_port(&args(list)).is_none(), "{list:?}");
            assert!(refusal_with_port(&args(list)).is_some(), "{list:?}");
        }
    }

    #[test]
    fn options_without_a_firmware_action_are_not_refused() {
        for list in [&["--eeprom-wipe", "p"][..], &["--rom", "p"][..]] {
            assert!(refusal_with_port(&args(list)).is_none(), "{list:?}");
        }
        let parsed = args(&[
            "--nocheck",
            "--fw-url",
            "x",
            "--hwrev",
            "3",
            "--platform",
            "80",
            "-U",
            "--show-psk",
            "--sign",
            "--wifi",
            "ap",
            "-i",
            "p",
        ]);
        assert!(refusal_without_port(&parsed).is_none());
        assert!(refusal_with_port(&parsed).is_none());
    }
}
