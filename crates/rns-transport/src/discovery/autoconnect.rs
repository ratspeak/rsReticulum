//! Which discovered interfaces may be auto-connected
//! (`InterfaceDiscovery.autoconnect_qualified`, Discovery.py:782-798).

use super::app_data::DiscoveryInfo;
use super::constants::{AUTOCONNECT_INTERFACE_TYPES, AUTOCONNECT_MINIMUM_VERSIONS};

/// A Backbone interface whose stack is at least the trusted release of its
/// implementation, or any Backbone interface when `allow_unverified`
/// (`autoconnect_unverified_implementations`) is set.
pub fn qualifies(info: &DiscoveryInfo, allow_unverified: bool) -> bool {
    if !AUTOCONNECT_INTERFACE_TYPES.contains(&info.interface_type.as_str()) {
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
/// component, up to the first without any (Discovery.py:995-1005).
fn version_tuple(version: &str) -> Option<Vec<u64>> {
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
            ..Default::default()
        }
    }

    /// Python 1.5.5 auto-connects only to "RNS" 1.5.2 or later
    /// (Discovery.py:486-487, :782-790).
    #[test]
    fn python_backbones_qualify_from_1_5_2() {
        assert!(qualifies(&backbone(Some("RNS"), Some("1.5.2")), false));
        assert!(qualifies(&backbone(Some("RNS"), Some("1.5.10")), false));
        assert!(qualifies(&backbone(Some("RNS"), Some("1.6")), false));
        assert!(qualifies(&backbone(Some("RNS"), Some("1.5.2rc1")), false));
        assert!(!qualifies(&backbone(Some("RNS"), Some("1.5.1")), false));
        assert!(!qualifies(&backbone(Some("RNS"), Some("1.5")), false));
        assert!(!qualifies(&backbone(Some("RNS"), Some("")), false));
        assert!(!qualifies(&backbone(Some("RNS"), Some("next")), false));
        assert!(!qualifies(&backbone(Some("RNS"), None), false));
    }

    /// rsRNS hubs need the unverified opt-in, as unknown stacks and announces
    /// without an implementation do.
    #[test]
    fn rust_and_unknown_stacks_need_the_unverified_opt_in() {
        for info in [
            backbone(Some("rsRNS"), Some(env!("CARGO_PKG_VERSION"))),
            backbone(Some("rsRNS"), Some("99.0.0")),
            backbone(Some("OtherRNS"), Some("9.9.9")),
            backbone(None, Some("1.5.5")),
            backbone(None, None),
        ] {
            assert!(!qualifies(&info, false), "{info:?}");
            assert!(qualifies(&info, true), "{info:?}");
        }
    }

    /// Python auto-connects only Backbone interfaces (Discovery.py:483, :798).
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
