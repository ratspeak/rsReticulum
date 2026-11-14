//! Operations this build refuses, checked where upstream `rnodeconf` would
//! start them.

use super::Args;

/// Flows upstream runs without a serial port.
pub fn refusal_without_port(args: &Args) -> Option<String> {
    if args.autoinstall {
        return Some("firmware autoinstall is not implemented yet".to_string());
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
    fn only_autoinstall_is_refused() {
        assert!(refusal_without_port(&args(&["-a"])).is_some());
        for list in [
            &["--flash", "p"][..],
            &["--update", "p"][..],
            &["--rom", "p"][..],
            &["--eeprom-wipe", "p"][..],
            &["-e", "p"][..],
        ] {
            assert!(refusal_without_port(&args(list)).is_none(), "{list:?}");
        }
    }
}
