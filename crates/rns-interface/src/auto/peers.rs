//! Peer table for AutoInterface (`peers`, `spawned_interfaces`,
//! `multicast_echoes` and `add_peer` in RNS/Interfaces/AutoInterface.py).

use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::mpsc;

use super::MultiIfDedup;
use crate::traits::InterfaceId;

/// The spawned `AutoInterfacePeer` registration for one peer.
#[derive(Debug, Clone)]
pub(super) struct ChildLink {
    pub id: InterfaceId,
    /// Feeds the child's read task, which hands packets to transport.
    pub inbound: mpsc::Sender<Bytes>,
    pub online: Arc<AtomicBool>,
    pub rxb: Arc<AtomicU64>,
}

#[derive(Debug)]
pub(super) struct Peer {
    pub ifname: String,
    pub scope_id: u32,
    pub last_heard: Instant,
    pub last_outbound: Instant,
    pub child: Option<ChildLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Discovered {
    /// Our own beacon came back on the named adopted interface.
    Echo(String),
    /// One of our addresses that no adopted interface currently selects.
    UnexpectedEcho,
    /// A new peer; the caller spawns its child interface.
    Added,
    Refreshed,
}

#[derive(Debug, Default)]
pub(super) struct Core {
    peers: HashMap<Ipv6Addr, Peer>,
    adopted: HashMap<String, Ipv6Addr>,
    own_addrs: HashMap<String, Vec<Ipv6Addr>>,
    echoes: HashMap<String, Instant>,
    initial_echoes: HashSet<String>,
    timed_out: HashMap<String, bool>,
    dedup: MultiIfDedup,
}

impl Core {
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// `link_local` is the selected address; `all` lists every link-local
    /// address of the interface (`link_local_addresses`).
    pub fn adopt(&mut self, ifname: &str, link_local: Ipv6Addr, all: &[Ipv6Addr], now: Instant) {
        self.adopted.insert(ifname.to_string(), link_local);
        self.own_addrs.insert(ifname.to_string(), all.to_vec());
        self.echoes.insert(ifname.to_string(), now);
    }

    pub fn release(&mut self, ifname: &str) {
        self.adopted.remove(ifname);
        self.own_addrs.remove(ifname);
        self.echoes.remove(ifname);
        self.initial_echoes.remove(ifname);
        self.timed_out.remove(ifname);
    }

    pub fn adopted(&self, ifname: &str) -> Option<Ipv6Addr> {
        self.adopted.get(ifname).copied()
    }

    pub fn adopted_ifnames(&self) -> Vec<String> {
        self.adopted.keys().cloned().collect()
    }

    pub fn last_echo(&self, ifname: &str) -> Option<Instant> {
        self.echoes.get(ifname).copied()
    }

    pub fn echo_received(&self, ifname: &str) -> bool {
        self.initial_echoes.contains(ifname)
    }

    /// Record the echo-timeout state, returning the previous one.
    pub fn set_timed_out(&mut self, ifname: &str, timed_out: bool) -> Option<bool> {
        self.timed_out.insert(ifname.to_string(), timed_out)
    }

    /// `add_peer` (AutoInterface.py:526-607): a beacon from `addr` passed the
    /// token check on `ifname`.
    pub fn discovered(
        &mut self,
        addr: Ipv6Addr,
        ifname: &str,
        scope_id: u32,
        now: Instant,
    ) -> Discovered {
        if let Some(own) = self
            .adopted
            .iter()
            .find(|(_, ll)| **ll == addr)
            .map(|(name, _)| name.clone())
        {
            self.echoes.insert(own.clone(), now);
            self.initial_echoes.insert(own.clone());
            return Discovered::Echo(own);
        }
        if self.own_addrs.values().any(|addrs| addrs.contains(&addr)) {
            return Discovered::UnexpectedEcho;
        }
        if let Some(peer) = self.peers.get_mut(&addr) {
            peer.last_heard = now;
            return Discovered::Refreshed;
        }
        self.peers.insert(
            addr,
            Peer {
                ifname: ifname.to_string(),
                scope_id,
                last_heard: now,
                last_outbound: now,
                child: None,
            },
        );
        Discovered::Added
    }

    /// Install the child spawned for a peer, returning any child it replaces.
    /// Returns the child back if the peer has gone in the meantime.
    pub fn attach(
        &mut self,
        addr: Ipv6Addr,
        child: ChildLink,
    ) -> Result<Option<ChildLink>, ChildLink> {
        match self.peers.get_mut(&addr) {
            Some(peer) => Ok(peer.child.replace(child)),
            None => Err(child),
        }
    }

    /// `process_incoming` of the parent and the peer child
    /// (AutoInterface.py:613-615, :652-668): only data from a source with a
    /// spawned child is delivered, duplicates seen on another NIC within the
    /// TTL are dropped, and delivered data refreshes the peer.
    pub fn inbound(&mut self, src: Ipv6Addr, data: &[u8], now: Instant) -> Option<ChildLink> {
        let child = self.peers.get(&src)?.child.as_ref()?;
        if !child.online.load(std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        let child = child.clone();
        if self.dedup.is_duplicate(data) {
            return None;
        }
        if let Some(peer) = self.peers.get_mut(&src) {
            peer.last_heard = now;
        }
        Some(child)
    }

    /// Timed-out peers (`peer_jobs`, AutoInterface.py:382-396).
    pub fn expire(&mut self, now: Instant, peering_timeout: f64) -> Vec<(Ipv6Addr, Peer)> {
        let expired: Vec<Ipv6Addr> = self
            .peers
            .iter()
            .filter(|(_, peer)| now.duration_since(peer.last_heard).as_secs_f64() > peering_timeout)
            .map(|(addr, _)| *addr)
            .collect();
        expired
            .into_iter()
            .filter_map(|addr| self.peers.remove(&addr).map(|peer| (addr, peer)))
            .collect()
    }

    /// Peers due a reverse peering beacon (AutoInterface.py:398-408).
    pub fn reverse_due(&mut self, now: Instant, interval: f64) -> Vec<(Ipv6Addr, String, u32)> {
        let mut due = Vec::new();
        for (addr, peer) in &mut self.peers {
            if now.duration_since(peer.last_outbound).as_secs_f64() > interval {
                peer.last_outbound = now;
                due.push((*addr, peer.ifname.clone(), peer.scope_id));
            }
        }
        due
    }

    /// Drop the child of `addr` if it is still the one with `id`.
    pub fn clear_child(&mut self, addr: Ipv6Addr, id: InterfaceId) {
        if let Some(peer) = self.peers.get_mut(&addr)
            && peer.child.as_ref().is_some_and(|c| c.id == id)
        {
            peer.child = None;
        }
    }

    pub fn drain_children(&mut self) -> Vec<ChildLink> {
        self.peers
            .values_mut()
            .filter_map(|peer| peer.child.take())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    fn addr(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn child(id: InterfaceId) -> (ChildLink, mpsc::Receiver<Bytes>) {
        let (tx, rx) = mpsc::channel(8);
        (
            ChildLink {
                id,
                inbound: tx,
                online: Arc::new(AtomicBool::new(true)),
                rxb: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    #[test]
    fn own_address_is_an_echo_not_a_peer() {
        let mut core = Core::default();
        let now = Instant::now();
        core.adopt("eth0", addr("fe80::1"), &[addr("fe80::1")], now);
        assert_eq!(
            core.discovered(addr("fe80::1"), "eth0", 2, now),
            Discovered::Echo("eth0".into())
        );
        assert!(core.echo_received("eth0"));
        assert_eq!(core.peers.len(), 0);
    }

    #[test]
    fn echo_is_credited_to_the_interface_owning_the_address() {
        let mut core = Core::default();
        let now = Instant::now();
        core.adopt("eth0", addr("fe80::1"), &[addr("fe80::1")], now);
        core.adopt("wlan0", addr("fe80::2"), &[addr("fe80::2")], now);
        assert_eq!(
            core.discovered(addr("fe80::2"), "eth0", 2, now),
            Discovered::Echo("wlan0".into())
        );
        assert!(!core.echo_received("eth0"));
    }

    #[test]
    fn secondary_own_address_is_neither_echo_nor_peer() {
        let mut core = Core::default();
        let now = Instant::now();
        core.adopt(
            "eth0",
            addr("fe80::2"),
            &[addr("fe80::1"), addr("fe80::2")],
            now,
        );
        assert_eq!(
            core.discovered(addr("fe80::1"), "eth0", 2, now),
            Discovered::UnexpectedEcho
        );
        assert_eq!(core.peers.len(), 0);
    }

    #[test]
    fn a_peer_is_keyed_by_address_and_keeps_its_first_interface() {
        let mut core = Core::default();
        let now = Instant::now();
        let p = addr("fe80::dead:beef:cafe:1234");
        assert_eq!(core.discovered(p, "eth0", 2, now), Discovered::Added);
        assert_eq!(core.discovered(p, "wlan0", 3, now), Discovered::Refreshed);
        assert_eq!(core.peers.len(), 1);
        assert_eq!(core.peers[&p].ifname, "eth0");
        assert_eq!(core.peers[&p].scope_id, 2);
    }

    #[test]
    fn data_from_unknown_source_or_childless_peer_is_dropped() {
        let mut core = Core::default();
        let now = Instant::now();
        assert!(core.inbound(addr("fe80::9"), b"x", now).is_none());
        let p = addr("fe80::5");
        core.discovered(p, "eth0", 2, now);
        assert!(core.inbound(p, b"x", now).is_none());
    }

    #[test]
    fn delivered_data_refreshes_the_peer_and_duplicates_do_not() {
        let mut core = Core::default();
        let t0 = Instant::now();
        let p = addr("fe80::5");
        core.discovered(p, "eth0", 2, t0);
        let (c, _rx) = child(7);
        assert!(core.attach(p, c).unwrap().is_none());
        let t1 = t0 + Duration::from_secs(10);
        assert_eq!(core.inbound(p, b"one", t1).map(|c| c.id), Some(7));
        assert_eq!(core.peers[&p].last_heard, t1);
        let t2 = t1 + Duration::from_millis(100);
        assert!(core.inbound(p, b"one", t2).is_none());
        assert_eq!(core.peers[&p].last_heard, t1);
    }

    #[test]
    fn offline_child_receives_nothing() {
        let mut core = Core::default();
        let now = Instant::now();
        let p = addr("fe80::5");
        core.discovered(p, "eth0", 2, now);
        let (c, _rx) = child(7);
        c.online.store(false, Ordering::SeqCst);
        core.attach(p, c).unwrap();
        assert!(core.inbound(p, b"x", now).is_none());
    }

    #[test]
    fn peers_expire_strictly_after_the_timeout() {
        let mut core = Core::default();
        let t0 = Instant::now();
        let p = addr("fe80::5");
        core.discovered(p, "eth0", 2, t0);
        assert!(core.expire(t0 + Duration::from_secs(22), 22.0).is_empty());
        let gone = core.expire(t0 + Duration::from_millis(22_001), 22.0);
        assert_eq!(gone.len(), 1);
        assert_eq!(core.peers.len(), 0);
    }

    #[test]
    fn reverse_peering_is_due_after_the_interval_and_then_resets() {
        let mut core = Core::default();
        let t0 = Instant::now();
        let p = addr("fe80::5");
        core.discovered(p, "eth0", 2, t0);
        assert!(
            core.reverse_due(t0 + Duration::from_secs(5), 5.2)
                .is_empty()
        );
        let t1 = t0 + Duration::from_secs(6);
        assert_eq!(core.reverse_due(t1, 5.2), vec![(p, "eth0".to_string(), 2)]);
        assert!(
            core.reverse_due(t1 + Duration::from_secs(1), 5.2)
                .is_empty()
        );
    }

    #[test]
    fn attach_to_a_forgotten_peer_hands_the_child_back() {
        let mut core = Core::default();
        let (c, _rx) = child(3);
        assert!(core.attach(addr("fe80::5"), c).is_err());
    }
}
