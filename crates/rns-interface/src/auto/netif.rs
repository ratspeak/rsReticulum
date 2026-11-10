//! Host NIC enumeration for AutoInterface.

use std::net::Ipv6Addr;

use super::{AutoPlatform, interface_selectable};

/// One enumerated host NIC, returned by [`list_network_interfaces`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub addr_v4: Option<String>,
    pub addr_v6_link_local: Option<String>,
    pub is_up: bool,
    pub is_loopback: bool,
}

/// Enumerate addresses reported by the host and group them by NIC name,
/// including loopback and normally ignored names. Callers apply filters.
/// `is_up` means an address was found; it is not a carrier or reachability test.
pub fn list_network_interfaces() -> Result<Vec<NetworkInterfaceInfo>, String> {
    use std::collections::BTreeMap;

    let mut by_name: BTreeMap<String, NetworkInterfaceInfo> = BTreeMap::new();
    let ifaces =
        if_addrs::get_if_addrs().map_err(|e| format!("if_addrs::get_if_addrs() failed: {e}"))?;
    for iface in ifaces {
        let entry = by_name
            .entry(iface.name.clone())
            .or_insert_with(|| NetworkInterfaceInfo {
                name: iface.name.clone(),
                addr_v4: None,
                addr_v6_link_local: None,
                is_up: false,
                is_loopback: iface.is_loopback(),
            });
        entry.is_loopback = entry.is_loopback || iface.is_loopback();
        match iface.addr.ip() {
            std::net::IpAddr::V4(v4) => {
                if entry.addr_v4.is_none() {
                    entry.addr_v4 = Some(v4.to_string());
                }
                entry.is_up = true;
            }
            std::net::IpAddr::V6(v6) => {
                // fe80::/10 — link-local prefix used by AutoInterface discovery.
                if (v6.segments()[0] & 0xffc0) == 0xfe80 && entry.addr_v6_link_local.is_none() {
                    entry.addr_v6_link_local = Some(v6.to_string());
                }
                entry.is_up = true;
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        match darwin_link_local_addrs(None, &[], false) {
            Ok(addrs) => {
                for (name, addr, _) in addrs {
                    let entry =
                        by_name
                            .entry(name.clone())
                            .or_insert_with(|| NetworkInterfaceInfo {
                                name,
                                addr_v4: None,
                                addr_v6_link_local: None,
                                is_up: true,
                                is_loopback: false,
                            });
                    entry.addr_v6_link_local = Some(addr.to_string());
                    entry.is_up = true;
                }
            }
            Err(e) => tracing::debug!(error = %e, "Darwin getifaddrs link-local list failed"),
        }
    }

    Ok(by_name.into_values().collect())
}

/// Clear the scope that BSD kernels embed in the second segment of a
/// link-local address (`descope_linklocal`, AutoInterface.py:80-85).
#[cfg(any(target_os = "macos", test))]
fn normalize_link_local_addr(addr: Ipv6Addr) -> Ipv6Addr {
    if (addr.segments()[0] & 0xffc0) != 0xfe80 {
        return addr;
    }
    let mut segments = addr.segments();
    segments[1] = 0;
    Ipv6Addr::from(segments)
}

fn passes_filters(
    iface_name: &str,
    devices: Option<&[String]>,
    ignored_devices: &[String],
) -> bool {
    interface_selectable(AutoPlatform::CURRENT, iface_name, devices, ignored_devices)
}

/// Enumerate link-local IPv6 addresses, applying device/ignore filters.
/// Drops addresses with unresolvable scope id — `scope_id = 0` silently
/// routes via the default NIC, which is wrong on multi-homed hosts.
pub(super) fn get_link_local_addrs(
    devices: Option<&[String]>,
    ignored_devices: &[String],
) -> Vec<(String, Ipv6Addr, u32)> {
    // Android's libc getifaddrs() hides IPv6 link-local from app context;
    // must use Java NetworkInterface.getNetworkInterfaces() via JNI.
    #[cfg(target_os = "android")]
    {
        match get_link_local_addrs_android(devices, ignored_devices) {
            Ok(v) if !v.is_empty() => {
                tracing::info!(count = v.len(), "Android JNI link-local enumerate");
                return v;
            }
            Ok(_) => {
                tracing::warn!(
                    "Android JNI link-local enumerate returned 0 — falling back to if_addrs"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "Android JNI link-local enumerate failed");
            }
        }
    }

    let mut result = Vec::new();
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => {
            tracing::debug!(count = ifaces.len(), "if_addrs enumerated interfaces");
            for iface in ifaces {
                tracing::debug!(name = %iface.name, addr = ?iface.addr.ip(), "if_addrs entry");
                if !passes_filters(&iface.name, devices, ignored_devices) {
                    continue;
                }
                if let std::net::IpAddr::V6(addr) = iface.addr.ip()
                    && (addr.segments()[0] & 0xffc0) == 0xfe80
                {
                    let scope_id = iface_scope_id(&iface);
                    if scope_id == 0 {
                        tracing::warn!(
                            iface = %iface.name,
                            addr = %addr,
                            "skipping link-local: could not resolve scope id (would send on wrong NIC)"
                        );
                        continue;
                    }
                    result.push((iface.name.clone(), addr, scope_id));
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "if_addrs::get_if_addrs() failed");
        }
    }

    #[cfg(target_os = "macos")]
    if result.is_empty() {
        match darwin_link_local_addrs(devices, ignored_devices, true) {
            Ok(addrs) if !addrs.is_empty() => {
                tracing::debug!(
                    count = addrs.len(),
                    "Darwin getifaddrs link-local enumerate"
                );
                return addrs;
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "Darwin getifaddrs link-local enumerate failed"),
        }
    }

    result
}

#[cfg(target_os = "macos")]
fn darwin_link_local_addrs(
    devices: Option<&[String]>,
    ignored_devices: &[String],
    apply_filters: bool,
) -> Result<Vec<(String, Ipv6Addr, u32)>, String> {
    use std::ffi::CStr;
    use std::ptr;

    let mut ifap: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: getifaddrs initialises `ifap` on success; the linked list is
    // released with freeifaddrs before return.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    struct IfAddrsGuard(*mut libc::ifaddrs);
    impl Drop for IfAddrsGuard {
        fn drop(&mut self) {
            // SAFETY: pointer came from successful getifaddrs and is released once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _guard = IfAddrsGuard(ifap);

    let mut result = Vec::new();
    let mut cursor = ifap;
    while !cursor.is_null() {
        // SAFETY: cursor walks the null-terminated getifaddrs list.
        let ifa = unsafe { &*cursor };
        cursor = ifa.ifa_next;

        if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: getifaddrs provides a nul-terminated interface name.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        if apply_filters && !passes_filters(&name, devices, ignored_devices) {
            continue;
        }
        if ifa.ifa_flags & libc::IFF_UP as u32 == 0 {
            continue;
        }
        // SAFETY: ifa_addr is non-null and points to a sockaddr for this entry.
        let family = unsafe { (*ifa.ifa_addr).sa_family as i32 };
        if family != libc::AF_INET6 {
            continue;
        }

        // SAFETY: family is AF_INET6, so sockaddr_in6 layout is valid.
        let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
        let addr = normalize_link_local_addr(Ipv6Addr::from(sin6.sin6_addr.s6_addr));
        if (addr.segments()[0] & 0xffc0) != 0xfe80 {
            continue;
        }

        let scope_id = if sin6.sin6_scope_id != 0 {
            sin6.sin6_scope_id
        } else {
            iface_name_to_scope_id(&name)
        };
        if scope_id == 0 {
            tracing::warn!(
                iface = %name,
                addr = %addr,
                "skipping Darwin link-local: could not resolve scope id"
            );
            continue;
        }
        if result.iter().any(|(existing, _, _)| existing == &name) {
            continue;
        }
        tracing::debug!(iface = %name, addr = %addr, scope_id, "Darwin link-local found");
        result.push((name, addr, scope_id));
    }

    Ok(result)
}

#[cfg(target_os = "android")]
fn get_link_local_addrs_android(
    devices: Option<&[String]>,
    ignored_devices: &[String],
) -> Result<Vec<(String, Ipv6Addr, u32)>, String> {
    use jni::objects::JObject;

    let vm = crate::android_usb::java_vm().ok_or("JavaVM not initialized")?;
    let env = vm
        .attach_current_thread()
        .map_err(|e| format!("attach_current_thread: {e}"))?;

    let ni_class = env
        .find_class("java/net/NetworkInterface")
        .map_err(|e| format!("NetworkInterface class: {e}"))?;
    let inet6_class = env
        .find_class("java/net/Inet6Address")
        .map_err(|e| format!("Inet6Address class: {e}"))?;

    let ifaces_enum = env
        .call_static_method(
            ni_class,
            "getNetworkInterfaces",
            "()Ljava/util/Enumeration;",
            &[],
        )
        .map_err(|e| format!("getNetworkInterfaces: {e}"))?
        .l()
        .map_err(|e| format!("getNetworkInterfaces obj: {e}"))?;
    if ifaces_enum.is_null() {
        return Err("getNetworkInterfaces returned null".into());
    }

    let mut result: Vec<(String, Ipv6Addr, u32)> = Vec::new();

    while env
        .call_method(ifaces_enum, "hasMoreElements", "()Z", &[])
        .map_err(|e| format!("hasMoreElements: {e}"))?
        .z()
        .map_err(|e| format!("hasMoreElements bool: {e}"))?
    {
        let iface_obj: JObject = env
            .call_method(ifaces_enum, "nextElement", "()Ljava/lang/Object;", &[])
            .map_err(|e| format!("nextElement (iface): {e}"))?
            .l()
            .map_err(|e| format!("nextElement iface obj: {e}"))?;
        if iface_obj.is_null() {
            continue;
        }

        let is_up = env
            .call_method(iface_obj, "isUp", "()Z", &[])
            .map_err(|e| format!("isUp: {e}"))?
            .z()
            .map_err(|e| format!("isUp bool: {e}"))?;
        if !is_up {
            continue;
        }

        let name_obj: JObject = env
            .call_method(iface_obj, "getName", "()Ljava/lang/String;", &[])
            .map_err(|e| format!("getName: {e}"))?
            .l()
            .map_err(|e| format!("getName obj: {e}"))?;
        let name: String = if name_obj.is_null() {
            String::new()
        } else {
            env.get_string(name_obj.into())
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default()
        };
        if !passes_filters(&name, devices, ignored_devices) {
            continue;
        }

        let scope_id = env
            .call_method(iface_obj, "getIndex", "()I", &[])
            .map_err(|e| format!("getIndex: {e}"))?
            .i()
            .map_err(|e| format!("getIndex int: {e}"))? as u32;
        if scope_id == 0 {
            tracing::warn!(
                iface = %name,
                "skipping JNI link-local: getIndex returned 0 (interface may have just gone down)"
            );
            continue;
        }

        let addrs_enum: JObject = env
            .call_method(
                iface_obj,
                "getInetAddresses",
                "()Ljava/util/Enumeration;",
                &[],
            )
            .map_err(|e| format!("getInetAddresses: {e}"))?
            .l()
            .map_err(|e| format!("getInetAddresses obj: {e}"))?;
        if addrs_enum.is_null() {
            continue;
        }

        while env
            .call_method(addrs_enum, "hasMoreElements", "()Z", &[])
            .map_err(|e| format!("addr hasMoreElements: {e}"))?
            .z()
            .map_err(|e| format!("addr hasMoreElements bool: {e}"))?
        {
            let addr_obj: JObject = env
                .call_method(addrs_enum, "nextElement", "()Ljava/lang/Object;", &[])
                .map_err(|e| format!("nextElement (addr): {e}"))?
                .l()
                .map_err(|e| format!("nextElement addr obj: {e}"))?;
            if addr_obj.is_null() {
                continue;
            }

            let is_v6 = env
                .is_instance_of(addr_obj, inet6_class)
                .map_err(|e| format!("is_instance_of Inet6Address: {e}"))?;
            if !is_v6 {
                continue;
            }

            let is_ll = env
                .call_method(addr_obj, "isLinkLocalAddress", "()Z", &[])
                .map_err(|e| format!("isLinkLocalAddress: {e}"))?
                .z()
                .map_err(|e| format!("isLinkLocalAddress bool: {e}"))?;
            if !is_ll {
                continue;
            }

            let raw_obj: JObject = env
                .call_method(addr_obj, "getAddress", "()[B", &[])
                .map_err(|e| format!("getAddress: {e}"))?
                .l()
                .map_err(|e| format!("getAddress obj: {e}"))?;
            if raw_obj.is_null() {
                continue;
            }
            let raw: Vec<u8> = env
                .convert_byte_array(raw_obj.into_inner())
                .unwrap_or_default();
            if raw.len() != 16 {
                continue;
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&raw);
            let v6 = Ipv6Addr::from(bytes);
            tracing::info!(iface = %name, addr = %v6, scope_id, "JNI link-local found");
            result.push((name.clone(), v6, scope_id));
        }
    }

    Ok(result)
}

#[cfg(test)]
pub(super) fn scope_id_of(name: &str) -> u32 {
    iface_name_to_scope_id(name)
}

fn iface_scope_id(iface: &if_addrs::Interface) -> u32 {
    if let Some(index) = iface.index {
        return index;
    }

    #[cfg(windows)]
    {
        let adapter_index = iface_name_to_scope_id(&iface.adapter_name);
        if adapter_index != 0 {
            return adapter_index;
        }
    }

    iface_name_to_scope_id(&iface.name)
}

/// Convert interface name to scope ID via POSIX/Windows `if_nametoindex`.
/// Returns 0 if the lookup fails; callers must skip the address.
#[cfg(any(unix, windows))]
fn iface_name_to_scope_id(name: &str) -> u32 {
    use std::ffi::CString;
    if let Ok(cname) = CString::new(name) {
        // SAFETY: if_nametoindex takes a NUL-terminated C string and returns
        // an index or 0 on error, with no ownership implications.
        unsafe { libc_if_nametoindex(cname.as_ptr()) }
    } else {
        0
    }
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "if_nametoindex"]
    fn libc_if_nametoindex(ifname: *const std::ffi::c_char) -> u32;
}

#[cfg(windows)]
#[link(name = "iphlpapi")]
unsafe extern "C" {
    #[link_name = "if_nametoindex"]
    fn libc_if_nametoindex(ifname: *const std::ffi::c_char) -> u32;
}

#[cfg(not(any(unix, windows)))]
fn iface_name_to_scope_id(_name: &str) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_interface(name: &str, ip: Ipv6Addr, index: Option<u32>) -> if_addrs::Interface {
        let addr = if_addrs::IfAddr::V6(if_addrs::Ifv6Addr {
            ip,
            netmask: Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0),
            prefixlen: 64,
            broadcast: None,
        });

        #[cfg(windows)]
        {
            if_addrs::Interface {
                name: name.to_string(),
                addr,
                index,
                adapter_name: name.to_string(),
            }
        }
        #[cfg(not(windows))]
        {
            if_addrs::Interface {
                name: name.to_string(),
                addr,
                index,
            }
        }
    }

    #[test]
    fn scope_id_prefers_enumerated_interface_index() {
        let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let iface = test_interface("__ratspeak_missing_iface__", addr, Some(1234));
        assert_eq!(iface_scope_id(&iface), 1234);
    }

    #[test]
    fn normalize_link_local_addr_clears_embedded_scope_segment() {
        let addr = Ipv6Addr::new(0xfe80, 0x18, 0, 0, 0, 0, 0, 1);
        assert_eq!(
            normalize_link_local_addr(addr),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
        );
        let global = Ipv6Addr::new(0xfddd, 0xebe4, 0, 0, 0, 0, 0, 1);
        assert_eq!(normalize_link_local_addr(global), global);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn if_addrs_link_local_feature_is_enabled() {
        let proc_addrs = std::fs::read_to_string("/proc/net/if_inet6").unwrap_or_default();
        let host_has_link_local = proc_addrs.lines().any(|line| {
            line.split_whitespace()
                .nth(3)
                .is_some_and(|scope| scope.eq_ignore_ascii_case("20"))
        });
        if !host_has_link_local {
            return;
        }
        let addrs = if_addrs::get_if_addrs().expect("list network interfaces");
        assert!(
            addrs.iter().any(|iface| {
                matches!(&iface.addr, if_addrs::IfAddr::V6(addr) if addr.is_link_local())
            }),
            "Linux has link-local IPv6 addresses in /proc/net/if_inet6, but if-addrs returned none; \
             keep the workspace if-addrs dependency feature `link-local` enabled"
        );
    }
}
