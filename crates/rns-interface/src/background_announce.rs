//! Exact-channel optional lane shared by the built-in final writers.
#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android",
    test
))]
use bytes::Bytes;
#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android",
    test
))]
pub(crate) use rns_transport::background_egress::BackgroundAnnounceReceiver;
#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android",
    test
))]
use tokio::sync::mpsc;
#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android",
    test
))]
pub(crate) fn register(
    tx: &mpsc::Sender<Bytes>,
) -> Result<BackgroundAnnounceReceiver, crate::traits::InterfaceError> {
    BackgroundAnnounceReceiver::register(tx).map_err(|error| {
        crate::traits::InterfaceError::SendFailed(format!(
            "background announce registration failed: {error:?}"
        ))
    })
}

#[cfg(test)]
pub(crate) fn scheduled_actor(
    tx: mpsc::Sender<Bytes>,
) -> (
    tokio::task::JoinHandle<()>,
    mpsc::Sender<rns_transport::messages::TransportMessage>,
    Bytes,
) {
    scheduled_actor_with_backlog(tx, 1)
}

/// A saturated scheduler uses a sub-clock-resolution cap interval so every
/// explicit actor tick is a due window. Writer readiness remains independent.
#[cfg(test)]
pub(crate) fn scheduled_actor_with_backlog(
    tx: mpsc::Sender<Bytes>,
    count: usize,
) -> (
    tokio::task::JoinHandle<()>,
    mpsc::Sender<rns_transport::messages::TransportMessage>,
    Bytes,
) {
    use rns_transport::{
        actor::TransportActor,
        constants::{InterfaceDirection, InterfaceMode},
        messages::{InterfaceEntry, QueuedAnnounce},
    };
    let (mut actor, control) = TransportActor::new();
    let bitrate = if count > 1 { u64::MAX } else { 500 };
    let mut entry = InterfaceEntry::new(
        "radio with no name heuristic".into(),
        InterfaceMode::Full,
        InterfaceDirection::bidirectional(),
        bitrate,
        500,
        tx,
    );
    let identity = rns_identity::identity::Identity::new();
    let mut first = Bytes::new();
    for index in 0..count {
        let app = format!("test.background.{index}");
        let dest = rns_identity::destination::Destination::hash_from_name_and_identity(
            &app,
            Some(&identity.hash),
        );
        let announce =
            rns_identity::announce::AnnounceData::create(&identity, &app, None, None).unwrap();
        let header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Single,
                packet_type: rns_wire::flags::PacketType::Announce,
            },
            hops: 1,
            transport_id: None,
            destination_hash: dest,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend(announce.pack());
        let raw = Bytes::from(raw);
        if index == 0 {
            first = raw.clone();
        }
        entry.announce_queue.push(QueuedAnnounce {
            destination_hash: dest,
            time: rns_transport::now_f64(),
            hops: 1,
            raw,
        });
        actor.local_destinations.insert(dest);
    }
    actor.interfaces.insert(1, entry);
    (tokio::spawn(actor.run()), control, first)
}
