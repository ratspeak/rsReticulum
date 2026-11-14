//! Start-up restores the routing snapshot, saved every 300 s, and the
//! known-destinations store, flushed every 10 s (Transport.py, Identity.py).
//! An entry rebuilt from a path's cached announce must not shadow what the
//! store learned since.
#![cfg(feature = "sqlite-store")]

use super::*;
use rns_wire::context::PacketContext;

fn announce(
    identity: &rns_identity::identity::Identity,
    app_name: &str,
    ratchet: Option<&[u8; 32]>,
    wire_time: u64,
    context: PacketContext,
) -> (Bytes, [u8; 16]) {
    let data = rns_identity::announce::AnnounceData::create_at(
        identity, app_name, None, ratchet, wire_time,
    )
    .unwrap();
    let dest = rns_identity::destination::Destination::hash_from_name_and_identity(
        app_name,
        Some(&identity.hash),
    );
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: ratchet.is_some(),
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        },
        hops: 2,
        transport_id: None,
        destination_hash: dest,
        context,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(&data.pack());
    (Bytes::from(raw), dest)
}

fn node(dir: &std::path::Path) -> TransportActor {
    let (mut actor, _) = TransportActor::new();
    actor.initialize_storage(dir.to_path_buf());
    let (mut entry, _rx) = make_test_interface("uplink");
    entry.ingress = crate::ingress::IngressController::disabled();
    actor.handle_message(TransportMessage::RegisterInterface { id: 1, entry });
    actor
}

fn inbound(actor: &mut TransportActor, raw: &Bytes) {
    actor.on_inbound(crate::messages::InboundPacket {
        raw: raw.clone(),
        interface_id: 1,
        rssi: None,
        snr: None,
        q: None,
    });
}

fn recalled_ratchet(actor: &mut TransportActor, dest: [u8; 16]) -> Option<[u8; 32]> {
    let TransportQueryResponse::RecalledDestination(entry) =
        actor.handle_query(TransportQuery::RecallDestination { dest })
    else {
        panic!("unexpected recall response");
    };
    entry.and_then(|entry| entry.ratchet)
}

/// Killed after the store flushed a rotated ratchet but before the next
/// routing snapshot: `Identity.get_ratchet` answers from the store
/// (Identity.py), not from the older announce the snapshot points at.
#[test]
fn a_restored_path_does_not_shadow_a_newer_stored_ratchet() {
    let dir = unique_temp_dir("restored-ratchet");
    let identity = rns_identity::identity::Identity::new();
    let now = crate::now_f64() as u64;
    let (old, new) = ([0x11; 32], [0x22; 32]);
    let (first, dest) = announce(
        &identity,
        "restored.ratchet",
        Some(&old),
        now - 60,
        PacketContext::None,
    );
    let (rotated, _) = announce(
        &identity,
        "restored.ratchet",
        Some(&new),
        now,
        PacketContext::None,
    );
    let mut before = node(&dir);
    inbound(&mut before, &first);
    assert!(before.path_table.has_path(&dest));
    before.on_shutdown();

    let mut killed = node(&dir);
    inbound(&mut killed, &rotated);
    killed.kd.shutdown(&killed.recent_announces, true);
    drop(killed);

    let mut restarted = node(&dir);
    assert_eq!(recalled_ratchet(&mut restarted, dest), Some(new));
    restarted.on_shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

/// The same window for the facts only this crate stores: first learned from
/// a hub's replay, then heard directly.
#[test]
fn a_restored_path_does_not_shadow_newer_stored_facts() {
    let dir = unique_temp_dir("restored-facts");
    let identity = rns_identity::identity::Identity::new();
    let now = crate::now_f64() as u64;
    let (replay, dest) = announce(
        &identity,
        "restored.facts",
        None,
        now - 60,
        PacketContext::PathResponse,
    );
    let (fresh, _) = announce(&identity, "restored.facts", None, now, PacketContext::None);
    let mut before = node(&dir);
    inbound(&mut before, &replay);
    assert!(before.path_table.has_path(&dest));
    before.on_shutdown();

    let mut killed = node(&dir);
    inbound(&mut killed, &fresh);
    killed.kd.shutdown(&killed.recent_announces, true);
    drop(killed);

    let mut restarted = node(&dir);
    let entry = &restarted.recent_announces[&dest];
    assert!(entry.facts_known && !entry.is_path_response);
    restarted.on_shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

/// `KnownDestinationsStore.remember_ratchet` queues nothing when the stored
/// row already holds the ratchet (Storage.py), so a ratchet heard again after
/// a restart keeps its first receive time, in memory as in the store.
#[test]
fn a_ratchet_heard_again_after_a_restart_keeps_its_stored_receive_time() {
    let dir = unique_temp_dir("restored-ratchet-received");
    let identity = rns_identity::identity::Identity::new();
    let now = crate::now_f64();
    let ratchet = [0x33; 32];
    let received = now - 3600.0;
    let (first, dest) = announce(
        &identity,
        "restored.received",
        None,
        now as u64 - 60,
        PacketContext::None,
    );
    let mut before = node(&dir);
    inbound(&mut before, &first);
    before.kd.remember_ratchet(dest, ratchet, received);
    before.on_shutdown();

    let mut restarted = node(&dir);
    let (again, _) = announce(
        &identity,
        "restored.received",
        Some(&ratchet),
        now as u64,
        PacketContext::None,
    );
    inbound(&mut restarted, &again);
    assert_eq!(
        restarted.kd.stored_ratchet(&dest),
        Some((ratchet, received))
    );
    assert_eq!(
        restarted.recent_announces[&dest].ratchet_received,
        Some(received)
    );
    restarted.on_shutdown();
    let _ = std::fs::remove_dir_all(dir);
}
