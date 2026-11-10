//! Operations this build refuses, checked where upstream `rnodeconf` would
//! start them: before the port check for portless flows, after it otherwise.

use super::Args;

/// Flows upstream runs without a serial port.
pub fn refusal_without_port(args: &Args) -> Option<String> {
    if args.trust_key.is_some() {
        return Some(
            "--trust-key is not yet safely supported; validated DER key enrollment is required"
                .to_string(),
        );
    }
    if args.public || args.key {
        return Some("signing key management is not fully implemented yet".to_string());
    }
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
    if args.flash || args.rom || args.update {
        return Some("firmware flashing is not implemented yet".to_string());
    }
    if args.eeprom_wipe {
        return Some(
            "--eeprom-wipe is destructive and is disabled until the full provisioning flow is implemented"
                .to_string(),
        );
    }
    if args.sign || args.firmware_hash.is_some() {
        return Some(
            "device signing and --firmware-hash write device trust state and are disabled until signing/provisioning is implemented"
                .to_string(),
        );
    }
    let mut families = Vec::new();
    if args.bluetooth_on || args.bluetooth_off || args.bluetooth_pair {
        families.push("Bluetooth");
    }
    if args.wifi.is_some()
        || args.channel.is_some()
        || args.ssid.is_some()
        || args.psk.is_some()
        || args.ip.is_some()
        || args.nm.is_some()
    {
        families.push("WiFi");
    }
    if args.display.is_some()
        || args.timeout.is_some()
        || args.rotation.is_some()
        || args.display_addr.is_some()
        || args.recondition_display
        || args.neopixel.is_some()
    {
        families.push("display");
    }
    if args.ia_enable || args.ia_disable {
        families.push("interference-avoidance");
    }
    (!families.is_empty()).then(|| {
        format!(
            "{} mutations are not yet safely supported",
            families.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn args(list: &[&str]) -> Args {
        Args::parse_from(std::iter::once("rnodeconf").chain(list.iter().copied()))
    }

    #[test]
    fn device_mutations_are_refused_only_once_a_port_is_given() {
        for list in [
            &["--bluetooth-on", "p"][..],
            &["--wifi", "off", "p"][..],
            &["--display", "10", "p"][..],
            &["--ia-enable", "p"][..],
            &["--eeprom-wipe", "p"][..],
            &["--sign", "p"][..],
            &["--rom", "p"][..],
        ] {
            assert!(refusal_without_port(&args(list)).is_none(), "{list:?}");
            assert!(refusal_with_port(&args(list)).is_some(), "{list:?}");
        }
    }

    #[test]
    fn firmware_options_without_a_firmware_action_are_ignored() {
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
            "-i",
            "p",
        ]);
        assert!(refusal_without_port(&parsed).is_none());
        assert!(refusal_with_port(&parsed).is_none());
    }
}
