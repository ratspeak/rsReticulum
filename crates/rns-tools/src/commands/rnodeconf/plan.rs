//! Side-effect-free command planning for the bounded `rnodeconf` slice.

use std::net::Ipv4Addr;

use rns_interface::{rnode, rnode_admin};

use super::{Args, frame};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePlan {
    pub mutation: Option<MutationPlan>,
    pub read_only: Vec<rnode_admin::AdminFrame>,
    pub show_psk: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationPlan {
    Tnc(rnode::RNodeRadioSettings),
    Normal,
}

impl DevicePlan {
    pub fn build(args: &Args) -> Result<Self, String> {
        validate_conflicts(args)?;
        validate_wifi_inputs(args)?;

        if args.show_psk && !args.config {
            return Err("--show-psk requires --config".to_string());
        }

        let radio = plan_radio(args)?;
        reject_unverified_mutations(args)?;

        let mutation = if args.normal {
            Some(MutationPlan::Normal)
        } else {
            radio.map(MutationPlan::Tnc)
        };

        let mut read_only = Vec::new();
        if args.info {
            read_only.extend(rnode_admin::detect_sequence());
            read_only.push(rnode_admin::eeprom_read_frame());
        }
        if args.config {
            read_only.push(frame(rnode::CMD_CFG_READ, &[0]));
        }
        if args.eeprom_dump || args.eeprom_backup {
            read_only.push(rnode_admin::eeprom_read_frame());
        }
        if args.get_target_firmware_hash {
            read_only.push(frame(rnode::CMD_HASHES, &[1]));
        }
        if args.get_firmware_hash {
            read_only.push(frame(rnode::CMD_HASHES, &[2]));
        }

        Ok(Self {
            mutation,
            read_only,
            show_psk: args.show_psk,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.mutation.is_none() && self.read_only.is_empty()
    }
}

fn validate_conflicts(args: &Args) -> Result<(), String> {
    if args.normal && args.tnc {
        return Err("--normal conflicts with --tnc".to_string());
    }

    let bluetooth_flags = [args.bluetooth_on, args.bluetooth_off, args.bluetooth_pair]
        .into_iter()
        .filter(|enabled| *enabled)
        .count();
    if bluetooth_flags > 1 {
        return Err(
            "--bluetooth-on, --bluetooth-off and --bluetooth-pair are mutually exclusive"
                .to_string(),
        );
    }

    if args.ia_enable && args.ia_disable {
        return Err("--ia-enable conflicts with --ia-disable".to_string());
    }

    Ok(())
}

fn plan_radio(args: &Args) -> Result<Option<rnode::RNodeRadioSettings>, String> {
    let fields = [
        args.freq.is_some(),
        args.bandwidth.is_some(),
        args.spreading_factor.is_some(),
        args.coding_rate.is_some(),
        args.tx_power.is_some(),
    ];
    let any = fields.iter().any(|present| *present);
    let all = fields.iter().all(|present| *present);

    if any && !args.tnc {
        return Err("RF settings are only allowed as a complete --tnc tuple".to_string());
    }
    if args.tnc && !all {
        return Err(
            "--tnc requires --freq, --bw, --sf, --cr and --txp as a complete tuple".to_string(),
        );
    }
    if !args.tnc {
        return Ok(None);
    }

    let settings = rnode::RNodeRadioSettings::new(
        args.freq.expect("tuple completeness checked"),
        args.bandwidth.expect("tuple completeness checked"),
        args.spreading_factor.expect("tuple completeness checked"),
        args.coding_rate.expect("tuple completeness checked"),
        args.tx_power.expect("tuple completeness checked"),
    );
    settings
        .validate()
        .map_err(|error| format!("invalid {}: {error}", error.field()))?;
    Ok(Some(settings))
}

fn validate_wifi_inputs(args: &Args) -> Result<(), String> {
    if let Some(mode) = args.wifi.as_deref() {
        match mode.to_ascii_lowercase().as_str() {
            "off" | "none" | "station" | "sta" | "ap" | "accesspoint" | "access_point" => {}
            _ => return Err("WiFi mode must be OFF, AP or STATION".to_string()),
        }
    }
    if let Some(channel) = args.channel {
        if !(1..=14).contains(&channel) {
            return Err("WiFi channel must be in 1..=14".to_string());
        }
    }
    if let Some(ssid) = args.ssid.as_deref() {
        if !ssid.eq_ignore_ascii_case("none") && ssid.len() > 32 {
            return Err("WiFi SSID must be at most 32 bytes".to_string());
        }
    }
    if let Some(psk) = args.psk.as_deref() {
        if !psk.eq_ignore_ascii_case("none") && !(8..=32).contains(&psk.len()) {
            return Err("WiFi PSK must be 8 to 32 bytes, or NONE".to_string());
        }
    }
    for (name, value) in [
        ("IP address", args.ip.as_deref()),
        ("netmask", args.nm.as_deref()),
    ] {
        if let Some(value) = value {
            if !value.eq_ignore_ascii_case("none") {
                value
                    .parse::<Ipv4Addr>()
                    .map_err(|error| format!("invalid WiFi {name} {value}: {error}"))?;
            }
        }
    }
    Ok(())
}

fn reject_unverified_mutations(args: &Args) -> Result<(), String> {
    let bluetooth = args.bluetooth_on || args.bluetooth_off || args.bluetooth_pair;
    let wifi = args.wifi.is_some()
        || args.channel.is_some()
        || args.ssid.is_some()
        || args.psk.is_some()
        || args.ip.is_some()
        || args.nm.is_some();
    let display = args.display.is_some()
        || args.timeout.is_some()
        || args.rotation.is_some()
        || args.display_addr.is_some()
        || args.recondition_display
        || args.neopixel.is_some();
    let interference_avoidance = args.ia_enable || args.ia_disable;

    let mut unsupported = Vec::new();
    if bluetooth {
        unsupported.push("Bluetooth");
    }
    if wifi {
        unsupported.push("WiFi");
    }
    if display {
        unsupported.push("display");
    }
    if interference_avoidance {
        unsupported.push("interference-avoidance");
    }
    if unsupported.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} mutations are not yet safely supported",
            unsupported.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn plan(args: &[&str]) -> Result<DevicePlan, String> {
        let args = Args::parse_from(std::iter::once("rnodeconf").chain(args.iter().copied()));
        DevicePlan::build(&args)
    }

    #[test]
    fn planner_builds_typed_tnc_and_preserves_radio_order() {
        let plan = plan(&[
            "--tnc",
            "--freq",
            "868000000",
            "--bw",
            "125000",
            "--sf",
            "7",
            "--cr",
            "5",
            "--txp",
            "14",
            "fake",
        ])
        .unwrap();
        let MutationPlan::Tnc(settings) = plan.mutation.unwrap() else {
            panic!("expected TNC plan");
        };
        let frames =
            rnode_admin::decode_frames(&rnode::build_radio_configuration_sequence(&settings));
        assert_eq!(
            frames.iter().map(|frame| frame.command).collect::<Vec<_>>(),
            vec![
                rnode::CMD_RADIO_STATE,
                rnode::CMD_FREQUENCY,
                rnode::CMD_BANDWIDTH,
                rnode::CMD_SF,
                rnode::CMD_CR,
                rnode::CMD_TXPOWER,
                rnode::CMD_RADIO_STATE,
            ]
        );
    }

    #[test]
    fn planner_rejects_conflicts_and_incomplete_or_detached_rf_tuples() {
        assert!(plan(&["--normal", "--tnc", "fake"]).is_err());
        assert!(plan(&["--bluetooth-on", "--bluetooth-off", "fake"]).is_err());
        assert!(plan(&["--ia-enable", "--ia-disable", "fake"]).is_err());
        assert!(plan(&["--tnc", "--freq", "868000000", "fake"]).is_err());
        assert!(plan(&["--freq", "868000000", "fake"]).is_err());
    }

    #[test]
    fn planner_rejects_generic_ranges_before_a_session_can_be_opened() {
        let result = plan(&[
            "--tnc",
            "--freq",
            "136999999",
            "--bw",
            "125000",
            "--sf",
            "7",
            "--cr",
            "5",
            "--txp",
            "14",
            "fake",
        ]);
        assert!(result.unwrap_err().contains("invalid frequency"));
    }

    #[test]
    fn invalid_wifi_is_rejected_before_unsupported_mutation_gate() {
        assert!(
            plan(&["--wifi", "bogus", "fake"])
                .unwrap_err()
                .contains("WiFi mode")
        );
        assert!(
            plan(&["--channel", "0", "fake"])
                .unwrap_err()
                .contains("channel")
        );
        assert!(
            plan(&["--ip", "999.1.1.1", "fake"])
                .unwrap_err()
                .contains("IP address")
        );
        assert!(
            plan(&["--psk", "short", "fake"])
                .unwrap_err()
                .contains("PSK")
        );
    }

    #[test]
    fn unacknowledged_mutation_families_fail_closed() {
        for args in [
            &["--bluetooth-on", "fake"][..],
            &["--wifi", "off", "fake"][..],
            &["--display", "10", "fake"][..],
            &["--ia-enable", "fake"][..],
        ] {
            assert!(plan(args).unwrap_err().contains("not yet safely supported"));
        }
    }

    #[test]
    fn show_psk_is_only_a_config_output_permission() {
        assert!(
            plan(&["--show-psk", "fake"])
                .unwrap_err()
                .contains("requires --config")
        );
        let plan = plan(&["--config", "--show-psk", "fake"]).unwrap();
        assert_eq!(plan.read_only.len(), 1);
        assert_eq!(plan.read_only[0].command, rnode::CMD_CFG_READ);
        assert!(
            plan.read_only
                .iter()
                .all(|frame| frame.command != rnode::CMD_WIFI_PSK)
        );
    }
}
