//! The IFAC passphrase must not survive in freed heap memory or show in
//! debug output.

#[path = "../../rns-crypto/tests/residue/mod.rs"]
mod residue;

use residue::{assert_no_residue, freed_by, serial};
use rns_runtime::config::ConfigSection;
use rns_runtime::interface_factory::InterfacePostInit;
use rns_runtime::reticulum::{RuntimeBackboneClientConfig, RuntimeInterfaceIfacConfig};

const PASSPHRASE: &str = "correct horse battery staple, twice";

#[test]
fn interface_options_free_no_ifac_passphrase() {
    let _serial = serial();
    let mut section = ConfigSection::new();
    section.set("networkname", "residue");
    section.set("passphrase", PASSPHRASE);

    let ((), freed) = freed_by(|| {
        let post_init = InterfacePostInit::try_from_section(&section).unwrap();
        assert!(post_init.ifac_passphrase.is_some());
    });

    assert_no_residue(&freed, &[("IFAC passphrase", PASSPHRASE.as_bytes())]);
}

#[test]
fn ifac_settings_debug_output_hides_the_passphrase() {
    let ifac = RuntimeInterfaceIfacConfig {
        network_name: Some("residue".into()),
        passphrase: Some(PASSPHRASE.into()),
        ifac_size: Some(16),
    };
    let backbone = RuntimeBackboneClientConfig {
        name: "residue",
        host: "127.0.0.1",
        port: 4242,
        prefer_ipv6: false,
        connect_timeout: None,
        max_reconnect_tries: None,
        ifac: Some(ifac.clone()),
    };

    for shown in [format!("{ifac:?}"), format!("{backbone:?}")] {
        assert!(!shown.contains(PASSPHRASE), "{shown}");
        assert!(shown.contains("residue"), "{shown}");
    }
}
