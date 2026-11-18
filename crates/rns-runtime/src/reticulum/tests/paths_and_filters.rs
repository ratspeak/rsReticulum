//! Runtime wiring for the path table and traffic filters: the config
//! directory's list files, per-interface hop limits and filter registrations.
use super::*;

#[test]
fn config_dir_type_lists_fill_the_filter_policy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("known_destination_types"),
        "# known\nlxmf.delivery\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("flagged_destination_types"), "spam.type\n").unwrap();
    let mut rc = ReticulumConfig::default();
    load_config_dir_lists(dir.path(), &mut rc);
    assert_eq!(rc.filter.known_types, ["lxmf.delivery"]);
    assert_eq!(rc.filter.flagged_types, ["spam.type"]);

    let empty = tempfile::tempdir().unwrap();
    let mut rc = ReticulumConfig::default();
    load_config_dir_lists(empty.path(), &mut rc);
    assert!(rc.filter.known_types.is_empty() && rc.filter.flagged_types.is_empty());
}

fn post_init(kind: &str, hop_limiter: &str) -> interface_factory::InterfacePostInit {
    let mut section = ConfigSection::new();
    section.set("type", kind);
    section.set("hop_limiter", hop_limiter);
    interface_factory::InterfacePostInit::try_from_section(&section).unwrap()
}

#[test]
fn hop_limiter_parses_like_upstream() {
    for (value, expected) in [
        ("3", Some(3)),
        ("300", Some(128)),
        ("0", None),
        ("-2", None),
    ] {
        assert_eq!(
            post_init("TCPClientInterface", value).hop_limiter,
            expected,
            "{value}"
        );
    }
    let mut section = ConfigSection::new();
    section.set("hop_limiter", "many");
    assert!(interface_factory::InterfacePostInit::try_from_section(&section).is_err());
    for (kind, spawned) in [
        ("TCPServerInterface", true),
        ("BackboneInterface", true),
        ("I2PInterface", true),
        ("AutoInterface", false),
        ("RNodeMultiInterface", false),
    ] {
        assert_eq!(post_init(kind, "3").spawned_hop_limiter, spawned, "{kind}");
    }
}

async fn registered_hop_limiter(transport_rx: &mut mpsc::Receiver<TransportMessage>) -> Option<u8> {
    let msg = transport_rx
        .recv()
        .await
        .map(unwrap_owned_event)
        .expect("registration");
    let TransportMessage::RegisterInterface { entry, .. } = msg else {
        panic!("expected RegisterInterface");
    };
    entry.hop_limiter
}

/// Reticulum.py sets `hop_limiter` on the configured interface; TCP server,
/// Backbone and I2P listeners copy it to accepted connections, while
/// AutoInterface peers, RNodeMulti subinterfaces and configured I2P peers
/// go without (bb63dd44).
#[tokio::test]
async fn hop_limiter_reaches_the_interfaces_upstream_gives_it() {
    let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
    let interface_controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let interface_registry = InterfaceRegistry::default();
    for (parent_id, kind, child_limit) in [
        (940_001, "TCPServerInterface", Some(3)),
        (940_011, "AutoInterface", None),
    ] {
        register_interface_with_post_init(
            &transport_tx,
            test_interface_handle(parent_id, None, kind),
            &post_init(kind, "3"),
            None,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
        )
        .await
        .unwrap();
        assert_eq!(
            registered_hop_limiter(&mut transport_rx).await,
            Some(3),
            "{kind}"
        );

        let (role, inherited, ifac_key, ifac_size) =
            child_registration_from_parent(&interface_controls, Some(parent_id));
        register_interface_handle_with_role_and_overrides(
            &transport_tx,
            test_interface_handle(parent_id + 1, Some(parent_id), "child"),
            role,
            inherited,
            ifac_key,
            ifac_size,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            registered_hop_limiter(&mut transport_rx).await,
            child_limit,
            "{kind}"
        );
    }

    register_interface_with_post_init(
        &transport_tx,
        test_interface_handle(940_021, Some(940_020), "RNodeMulti subinterface"),
        &post_init("RNodeMultiInterface", "3"),
        None,
        &interface_controls,
        &interface_registry,
        InterfaceKind::Standard,
    )
    .await
    .unwrap();
    assert_eq!(registered_hop_limiter(&mut transport_rx).await, None);

    register_owned_interface_with_post_init(
        &transport_tx,
        OwnedInterfaceHandle {
            configured_peer: true,
            ..test_interface_handle(940_031, None, "I2P to peer").into()
        },
        &post_init("I2PInterface", "3"),
        None,
        &interface_controls,
        &interface_registry,
        InterfaceKind::Standard,
        None,
    )
    .await
    .unwrap();
    assert_eq!(registered_hop_limiter(&mut transport_rx).await, None);
}

#[test]
fn blocked_ips_lines_parse_like_upstream() {
    let lines: Vec<String> = [
        "198.51.100.7",
        "2001:db8::1",
        "0:0:0:0:0:0:0:1",
        "198.51.100.0/24",
        "example.org",
        "198.51.100.8 # spammer",
        "",
    ]
    .map(String::from)
    .into();
    let parsed: Vec<String> = parse_blocked_ips(&lines)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(parsed, ["198.51.100.7", "2001:db8::1", "::1"]);
}
