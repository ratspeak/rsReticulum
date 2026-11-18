//! Interface-type and advertised-version filter for automatic connections.
//! This module decides eligibility only; it does not open a connection.

use super::app_data::DiscoveryInfo;
use super::constants::{AUTOCONNECT_INTERFACE_TYPES, AUTOCONNECT_MINIMUM_VERSIONS};

/// Check the advertised type, transport state and implementation/version
/// against the local auto-connect policy. Only a transport-enabled
/// `BackboneInterface` is eligible. With `allow_unverified`, any advertised
/// implementation/version qualifies; otherwise only `RNS` 1.5.7 or later and
/// `rsRNS` 1.5.0 or later do ([`AUTOCONNECT_MINIMUM_VERSIONS`]). Other or
/// missing implementations and missing or unparsable versions need the opt-in.
///
/// Comparison uses leading numeric components, as Python's tuples, not full
/// semantic-version rules: `1.5.0rc1` compares as `1.5.0`, and `1.5` sorts
/// below `1.5.0`. These are sender-supplied claims, not attestation. This
/// helper does not check freshness, endpoint validity, source permissions or
/// available connection slots.
pub fn qualifies(info: &DiscoveryInfo, allow_unverified: bool) -> bool {
    if !AUTOCONNECT_INTERFACE_TYPES.contains(&info.interface_type.as_str()) {
        return false;
    }
    // Upstream checks transport before the unverified bypass (Discovery.py).
    if !info.transport_enabled {
        return false;
    }
    if allow_unverified {
        return true;
    }
    let (Some(name), Some(version)) = (info.impl_name.as_deref(), info.impl_version.as_deref())
    else {
        return false;
    };
    let Some(minimum) = AUTOCONNECT_MINIMUM_VERSIONS
        .iter()
        .find(|(implementation, _)| *implementation == name)
        .and_then(|(_, minimum)| minimum.and_then(version_tuple))
    else {
        return false;
    };
    version_tuple(version).is_some_and(|version| version >= minimum)
}

/// Python's `version_tuple`: the leading digits of each dot-separated
/// component, up to the first without any (Discovery.py).
pub(crate) fn version_tuple(version: &str) -> Option<Vec<u64>> {
    let components: Vec<u64> = version
        .trim()
        .split('.')
        .map_while(|component| {
            let digits = component
                .find(|c: char| !c.is_ascii_digit())
                .map_or(component, |end| &component[..end]);
            (!digits.is_empty()).then(|| digits.parse().unwrap_or(u64::MAX))
        })
        .collect();
    (!components.is_empty()).then_some(components)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backbone(impl_name: Option<&str>, impl_version: Option<&str>) -> DiscoveryInfo {
        DiscoveryInfo {
            interface_type: "BackboneInterface".into(),
            impl_name: impl_name.map(str::to_string),
            impl_version: impl_version.map(str::to_string),
            transport_enabled: true,
            ..Default::default()
        }
    }

    /// Python 1.6.0 auto-connects only to "RNS" 1.5.7 or later
    /// (Discovery.py).
    #[test]
    fn python_backbones_qualify_from_1_5_7() {
        assert!(qualifies(&backbone(Some("RNS"), Some("1.5.7")), false));
        assert!(qualifies(&backbone(Some("RNS"), Some("1.5.10")), false));
        assert!(qualifies(&backbone(Some("RNS"), Some("1.6")), false));
        assert!(qualifies(&backbone(Some("RNS"), Some("1.5.7rc1")), false));
        assert!(!qualifies(&backbone(Some("RNS"), Some("1.5.6")), false));
        assert!(!qualifies(&backbone(Some("RNS"), Some("1.5")), false));
        assert!(!qualifies(&backbone(Some("RNS"), Some("")), false));
        assert!(!qualifies(&backbone(Some("RNS"), Some("next")), false));
        assert!(!qualifies(&backbone(Some("RNS"), None), false));
    }

    /// rsRNS hubs qualify from 1.5.0 without the opt-in; upstream trusts only
    /// "RNS", so this is a deliberate difference.
    #[test]
    fn rust_backbones_qualify_from_1_5_0() {
        assert_eq!(
            AUTOCONNECT_MINIMUM_VERSIONS,
            &[("RNS", Some("1.5.7")), ("rsRNS", Some("1.5.0"))]
        );
        for version in [
            crate::discovery::constants::IMPLEMENTATION_VERSION,
            "1.5.0",
            "1.5.0rc1",
            "1.5.0-rc1",
            "1.5.1",
            "1.6",
            "1.6.0",
            "2.0.0",
        ] {
            assert!(
                qualifies(&backbone(Some("rsRNS"), Some(version)), false),
                "{version}"
            );
        }
    }

    /// Without the opt-in, only the two known names at or above their floors
    /// qualify; with it, every one of these does.
    #[test]
    fn everything_else_needs_the_unverified_opt_in() {
        for info in [
            backbone(Some("rsRNS"), Some("1.4.9")),
            backbone(Some("rsRNS"), Some("1.4.0")),
            backbone(Some("rsRNS"), Some("1.5")),
            backbone(Some("rsRNS"), Some("")),
            backbone(Some("rsRNS"), Some("next")),
            backbone(Some("rsRNS"), None),
            backbone(Some("RNS"), Some("1.5.6")),
            backbone(Some("RNS"), None),
            backbone(Some("MeshChatX"), Some("9.9.9")),
            backbone(Some("rsrns"), Some("1.6.0")),
            backbone(Some(""), Some("1.6.0")),
            backbone(None, Some("1.6.0")),
            backbone(None, None),
        ] {
            assert!(!qualifies(&info, false), "{info:?}");
            assert!(qualifies(&info, true), "{info:?}");
        }
    }

    /// The transport requirement holds even with the unverified opt-in
    /// (Discovery.py).
    #[test]
    fn non_transport_interfaces_never_qualify() {
        for name in ["RNS", "rsRNS"] {
            let mut info = backbone(Some(name), Some("1.6.0"));
            info.transport_enabled = false;
            assert!(!qualifies(&info, false), "{name}");
            assert!(!qualifies(&info, true), "{name}");
        }
    }

    /// Python auto-connects only Backbone interfaces (Discovery.py).
    #[test]
    fn only_backbone_interfaces_are_auto_connected() {
        assert_eq!(AUTOCONNECT_INTERFACE_TYPES, &["BackboneInterface"]);
        let mut server = backbone(Some("RNS"), Some("1.5.5"));
        server.interface_type = "TCPServerInterface".into();
        assert!(!qualifies(&server, true));
    }

    #[test]
    fn versions_parse_like_python_version_tuple() {
        assert_eq!(version_tuple("1.5.2"), Some(vec![1, 5, 2]));
        assert_eq!(version_tuple(" 1.5.2 "), Some(vec![1, 5, 2]));
        assert_eq!(version_tuple("1.5.2rc1"), Some(vec![1, 5, 2]));
        assert_eq!(version_tuple("1.x.2"), Some(vec![1]));
        assert_eq!(version_tuple("v1.5"), None);
        assert_eq!(version_tuple(""), None);
    }
}
