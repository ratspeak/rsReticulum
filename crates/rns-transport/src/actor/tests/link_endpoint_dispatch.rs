use super::*;
use crate::link_endpoint_dispatch::{
    LinkEndpointDispatchBindReceipt, LinkEndpointDispatchError, LinkEndpointDispatchOutcome,
    LinkEndpointDispatchToken,
};
use crate::messages::LinkEndpointBindResult;
use std::time::Instant;
use tokio::sync::oneshot;

fn binding() -> LinkEndpointBinding {
    LinkEndpointBinding {
        link_id: [0xd3; 16],
        interface_id: 7,
        role: LinkEndpointRole::Responder,
    }
}

fn execute(actor: &mut TransportActor) {
    let operation = actor.link_endpoint_dispatch_rx.try_recv().unwrap();
    actor.handle_link_endpoint_dispatch(operation);
}

fn begin_bind(actor: &TransportActor) -> LinkEndpointDispatchBindReceipt {
    let (lifecycle_tx, _rx) = mpsc::unbounded_channel();
    actor
        .link_endpoint_dispatch_handle()
        .try_bind(binding(), lifecycle_tx)
        .unwrap()
}

fn bind(actor: &mut TransportActor) -> LinkEndpointDispatchToken {
    let mut receipt = begin_bind(actor);
    execute(actor);
    receipt.try_recv().unwrap().unwrap()
}

fn packet(tag: u8) -> OutboundRequest {
    let mut raw = make_link_data_packet_with_context(
        binding().link_id,
        0,
        rns_wire::context::PacketContext::None,
    )
    .to_vec();
    raw.push(tag);
    OutboundRequest {
        raw: raw.into(),
        destination_hash: binding().link_id,
    }
}

fn fixture() -> (TransportActor, mpsc::Receiver<Bytes>) {
    let (mut actor, _) = TransportActor::new();
    let (target, rx) = make_test_interface_with_capacity("dispatch target", 1);
    actor.interfaces.insert(7, target);
    (actor, rx)
}

#[test]
fn dispatch_receipt_waits_for_driver_and_preserves_mixed_legacy_fifo() {
    let (mut actor, mut rx) = fixture();
    let token = bind(&mut actor);
    actor.interfaces[&7]
        .tx
        .try_send(Bytes::from_static(b"occupied"))
        .unwrap();
    let first = packet(1);
    let second = packet(2);
    let third = packet(3);
    assert_eq!(
        actor.send_link_endpoint(binding().link_id, binding().role, packet(1)),
        LinkEndpointSendResult::Queued { depth: 1 }
    );
    let before = Instant::now();
    let mut receipt = token
        .try_send(packet(2), before + Duration::from_secs(1))
        .unwrap();
    execute(&mut actor);
    assert!(matches!(
        receipt.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(
        actor.send_link_endpoint(binding().link_id, binding().role, packet(3)),
        LinkEndpointSendResult::Queued { depth: 3 }
    );
    rx.try_recv().unwrap();
    actor.drain_link_endpoint_egress();
    assert_eq!(rx.try_recv().unwrap(), first.raw);
    assert!(matches!(
        receipt.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    let before_dispatch = Instant::now();
    actor.drain_link_endpoint_egress();
    let after_dispatch = Instant::now();
    assert_eq!(rx.try_recv().unwrap(), second.raw);
    std::thread::sleep(Duration::from_millis(2));
    let LinkEndpointDispatchOutcome::Sent {
        packet_hash,
        dispatched_at,
    } = receipt.try_recv().unwrap()
    else {
        panic!("expected driver admission");
    };
    assert!(dispatched_at >= before_dispatch && dispatched_at <= after_dispatch);
    assert!(dispatched_at < Instant::now());
    assert_eq!(
        packet_hash,
        rns_wire::hash::packet_hash(&second.raw, rns_wire::flags::HeaderType::Header1)
    );
    actor.drain_link_endpoint_egress();
    assert_eq!(rx.try_recv().unwrap(), third.raw);
}

#[test]
fn dispatch_expiry_and_cancellation_prune_behind_full_legacy_head() {
    let (mut actor, mut rx) = fixture();
    let token = bind(&mut actor);
    actor.interfaces[&7]
        .tx
        .try_send(Bytes::from_static(b"occupied"))
        .unwrap();
    let legacy = packet(1);
    actor.send_link_endpoint(binding().link_id, binding().role, packet(1));
    let mut expired = token
        .try_send(packet(2), Instant::now() + Duration::from_millis(5))
        .unwrap();
    execute(&mut actor);
    let cancelled = token
        .try_send(packet(3), Instant::now() + Duration::from_secs(1))
        .unwrap();
    execute(&mut actor);
    drop(cancelled);
    std::thread::sleep(Duration::from_millis(10));
    actor.drain_link_endpoint_egress();
    assert_eq!(
        expired.try_recv().unwrap(),
        LinkEndpointDispatchOutcome::Expired
    );
    assert_eq!(
        actor.link_endpoints[&(binding().link_id, binding().role)]
            .egress
            .len(),
        1
    );
    rx.try_recv().unwrap();
    actor.drain_link_endpoint_egress();
    assert_eq!(rx.try_recv().unwrap(), legacy.raw);
    actor.drain_link_endpoint_egress();
    assert!(rx.try_recv().is_err());
    assert!(
        actor
            .link_endpoints
            .contains_key(&(binding().link_id, binding().role))
    );
}

#[test]
fn dispatch_stale_generation_cannot_send_or_expire_replacement() {
    let (mut actor, mut rx) = fixture();
    let old = bind(&mut actor);
    let mut stale = old
        .try_send(packet(1), Instant::now() + Duration::from_secs(1))
        .unwrap();
    actor.unbind_link_endpoint(binding().link_id, binding().role);
    // The old request remains in the new private lane while the replacement
    // binds through the legacy API: same id, role and interface, new owner.
    let (lifecycle_tx, _lifecycle_rx) = mpsc::unbounded_channel();
    assert_eq!(
        actor.bind_link_endpoint(binding(), lifecycle_tx),
        LinkEndpointBindResult::Bound
    );
    execute(&mut actor);
    assert_eq!(
        stale.try_recv().unwrap(),
        LinkEndpointDispatchOutcome::Rejected(LinkEndpointSendResult::NotBound)
    );
    assert!(rx.try_recv().is_err());
    assert_eq!(
        actor.send_link_endpoint(binding().link_id, binding().role, packet(2)),
        LinkEndpointSendResult::Sent
    );
    assert!(rx.try_recv().is_ok());
    assert!(
        actor
            .link_endpoints
            .contains_key(&(binding().link_id, binding().role))
    );
}

#[test]
fn dispatch_unpublished_bind_cancellation_does_not_leak_or_retire_replacement() {
    let (mut actor, mut rx) = fixture();
    let before_execution = begin_bind(&actor);
    drop(before_execution);
    execute(&mut actor);
    assert!(actor.link_endpoints.is_empty());

    let after_execution = begin_bind(&actor);
    execute(&mut actor);
    assert_eq!(actor.link_endpoints.len(), 1);
    drop(after_execution);
    // Even a legacy send cannot use the canceled unpublished binding before
    // periodic maintenance gets a chance to retire it.
    assert_eq!(
        actor.send_link_endpoint(binding().link_id, binding().role, packet(1)),
        LinkEndpointSendResult::NotBound
    );
    assert!(actor.link_endpoints.is_empty());
    assert!(rx.try_recv().is_err());

    let old = begin_bind(&actor);
    execute(&mut actor);
    actor.unbind_link_endpoint(binding().link_id, binding().role);
    let replacement = bind(&mut actor);
    drop(old);
    actor.drain_link_endpoint_egress();
    let mut sent = replacement
        .try_send(packet(2), Instant::now() + Duration::from_secs(1))
        .unwrap();
    execute(&mut actor);
    assert!(matches!(
        sent.try_recv().unwrap(),
        LinkEndpointDispatchOutcome::Sent { .. }
    ));
    assert!(rx.try_recv().is_ok());
}

#[test]
fn dispatch_published_token_drop_keeps_explicit_endpoint_lifetime() {
    let (mut actor, mut rx) = fixture();
    let token = bind(&mut actor);
    drop(token);
    actor.drain_link_endpoint_egress();
    assert_eq!(
        actor.send_link_endpoint(binding().link_id, binding().role, packet(1)),
        LinkEndpointSendResult::Sent
    );
    assert!(rx.try_recv().is_ok());
}

#[test]
fn dispatch_cancelled_or_expired_mailbox_send_never_enters_fifo() {
    let (mut actor, mut rx) = fixture();
    let token = bind(&mut actor);
    let cancelled = token
        .try_send(packet(1), Instant::now() + Duration::from_secs(1))
        .unwrap();
    drop(cancelled);
    execute(&mut actor);
    let mut expired = token.try_send(packet(2), Instant::now()).unwrap();
    execute(&mut actor);
    assert_eq!(
        expired.try_recv().unwrap(),
        LinkEndpointDispatchOutcome::Expired
    );
    assert!(rx.try_recv().is_err());
    assert!(
        actor.link_endpoints[&(binding().link_id, binding().role)]
            .egress
            .is_empty()
    );
}

#[test]
fn dispatch_terminal_interface_removal_completes_queued_owner_once() {
    let (mut actor, mut rx) = fixture();
    let token = bind(&mut actor);
    actor.interfaces[&7]
        .tx
        .try_send(Bytes::from_static(b"occupied"))
        .unwrap();
    let mut pending = token
        .try_send(packet(1), Instant::now() + Duration::from_secs(1))
        .unwrap();
    execute(&mut actor);
    actor.deregister_interface(7);
    assert_eq!(
        pending.try_recv().unwrap(),
        LinkEndpointDispatchOutcome::Rejected(LinkEndpointSendResult::Terminated(
            LinkEndpointTerminalReason::InterfaceRemoved
        ))
    );
    assert_eq!(rx.try_recv().unwrap(), Bytes::from_static(b"occupied"));
    assert!(rx.try_recv().is_err());
    assert!(actor.link_endpoints.is_empty());
}

#[test]
fn dispatch_private_lane_and_packet_allocation_are_bounded() {
    let (mut actor, _rx) = fixture();
    let token = bind(&mut actor);
    assert!(matches!(
        token.try_send(packet(1), Instant::now() + Duration::from_secs(121)),
        Err(LinkEndpointDispatchError::InvalidDeadline)
    ));
    let mut huge = token
        .try_send(
            OutboundRequest {
                raw: Bytes::from(vec![0; 501]),
                destination_hash: binding().link_id,
            },
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(
        huge.try_recv().unwrap(),
        LinkEndpointDispatchOutcome::Rejected(LinkEndpointSendResult::InvalidPacket)
    );
    assert!(actor.link_endpoint_dispatch_rx.try_recv().is_err());
    let mut pending = Vec::new();
    for _ in 0..crate::link_endpoint_dispatch::DISPATCH_QUEUE_CAPACITY {
        pending.push(
            token
                .try_send(packet(1), Instant::now() + Duration::from_secs(1))
                .unwrap(),
        );
    }
    assert!(matches!(
        token.try_send(packet(1), Instant::now() + Duration::from_secs(1)),
        Err(LinkEndpointDispatchError::Full)
    ));
    drop(actor);
    assert!(matches!(
        token.try_send(packet(1), Instant::now() + Duration::from_secs(1)),
        Err(LinkEndpointDispatchError::Closed)
    ));
}

#[tokio::test]
async fn dispatch_real_actor_reports_admission_after_low_rtt_window_not_queue_acceptance() {
    let (mut actor, transport_tx) = TransportActor::new();
    let (target, mut rx) = make_test_interface_with_capacity("real actor target", 1);
    target.tx.try_send(Bytes::from_static(b"occupied")).unwrap();
    actor.interfaces.insert(7, target);
    let dispatch = actor.link_endpoint_dispatch_handle();
    let owner = tokio::spawn(actor.run());
    let (lifecycle_tx, _lifecycle_rx) = mpsc::unbounded_channel();
    let token = dispatch
        .try_bind(binding(), lifecycle_tx)
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    let mut sent = token
        .try_send(packet(1), Instant::now() + Duration::from_secs(2))
        .unwrap();
    // Five milliseconds is the new packet-proof floor. The canonical receipt
    // must remain pending throughout this interval while the driver is full.
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut sent)
            .await
            .is_err()
    );
    assert_eq!(rx.try_recv().unwrap(), Bytes::from_static(b"occupied"));
    let capacity_released = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(2), sent)
        .await
        .unwrap()
        .unwrap();
    let LinkEndpointDispatchOutcome::Sent { dispatched_at, .. } = outcome else {
        panic!("expected real driver admission");
    };
    assert!(dispatched_at >= capacity_released);
    assert_eq!(rx.try_recv().unwrap(), packet(1).raw);
    transport_tx.send(TransportMessage::Shutdown).await.unwrap();
    owner.await.unwrap();
}

#[test]
fn dispatch_rejected_duplicate_bind_does_not_adopt_or_cancel_original() {
    let (mut actor, mut rx) = fixture();
    let token = bind(&mut actor);
    let duplicate = begin_bind(&actor);
    execute(&mut actor);
    drop(duplicate);
    actor.drain_link_endpoint_egress();
    let mut sent = token
        .try_send(packet(1), Instant::now() + Duration::from_secs(1))
        .unwrap();
    execute(&mut actor);
    assert!(matches!(
        sent.try_recv().unwrap(),
        LinkEndpointDispatchOutcome::Sent { .. }
    ));
    assert!(rx.try_recv().is_ok());
    let mut duplicate = begin_bind(&actor);
    execute(&mut actor);
    assert!(matches!(
        duplicate.try_recv().unwrap(),
        Err(LinkEndpointBindResult::AlreadyBound)
    ));
}

#[test]
fn dispatch_fifo_exhaustion_is_bounded_and_resolves_every_queued_receipt() {
    let (mut actor, mut rx) = fixture();
    let token = bind(&mut actor);
    actor.interfaces[&7]
        .tx
        .try_send(Bytes::from_static(b"occupied"))
        .unwrap();
    let mut pending = Vec::new();
    for _ in 0..LINK_ENDPOINT_EGRESS_QUEUE_CAPACITY {
        pending.push(
            token
                .try_send(packet(1), Instant::now() + Duration::from_secs(1))
                .unwrap(),
        );
        execute(&mut actor);
    }
    assert_eq!(
        actor.link_endpoints[&(binding().link_id, binding().role)]
            .egress
            .len(),
        LINK_ENDPOINT_EGRESS_QUEUE_CAPACITY
    );
    pending.push(
        token
            .try_send(packet(2), Instant::now() + Duration::from_secs(1))
            .unwrap(),
    );
    execute(&mut actor);
    assert!(actor.link_endpoints.is_empty());
    for mut receipt in pending {
        assert_eq!(
            receipt.try_recv().unwrap(),
            LinkEndpointDispatchOutcome::Rejected(LinkEndpointSendResult::Terminated(
                LinkEndpointTerminalReason::EgressQueueExhausted
            ))
        );
    }
    assert_eq!(rx.try_recv().unwrap(), Bytes::from_static(b"occupied"));
    assert!(rx.try_recv().is_err());
}

#[test]
fn dispatch_local_peer_admission_and_transport_shutdown_have_exact_outcomes() {
    let (mut actor, _) = TransportActor::new();
    let (initiator_tx, mut initiator_rx) = mpsc::channel(1);
    let (responder_tx, _responder_rx) = mpsc::channel(1);
    actor.local_link_routes.insert(
        binding().link_id,
        LocalLinkRoute {
            initiator_tx,
            responder_tx,
        },
    );
    let local_binding = LinkEndpointBinding {
        interface_id: LOCAL_LINK_RESPONDER_INTERFACE,
        ..binding()
    };
    let (lifecycle_tx, _lifecycle_rx) = mpsc::unbounded_channel();
    let mut bound = actor
        .link_endpoint_dispatch_handle()
        .try_bind(local_binding, lifecycle_tx)
        .unwrap();
    execute(&mut actor);
    let token = bound.try_recv().unwrap().unwrap();
    assert_eq!(token.binding(), local_binding);
    let mut sent = token
        .try_send(packet(1), Instant::now() + Duration::from_secs(1))
        .unwrap();
    execute(&mut actor);
    assert!(matches!(
        sent.try_recv().unwrap(),
        LinkEndpointDispatchOutcome::Sent { .. }
    ));
    let mut pending = token
        .try_send(packet(2), Instant::now() + Duration::from_secs(1))
        .unwrap();
    execute(&mut actor);
    assert!(matches!(
        pending.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    actor.on_shutdown();
    assert_eq!(
        pending.try_recv().unwrap(),
        LinkEndpointDispatchOutcome::Rejected(LinkEndpointSendResult::Terminated(
            LinkEndpointTerminalReason::TransportShutdown
        ))
    );
    assert!(
        matches!(initiator_rx.try_recv().unwrap(), crate::link_messages::DestinationEvent::InboundPacket { raw, interface_id: LOCAL_LINK_INITIATOR_INTERFACE, .. } if raw == packet(1).raw)
    );
    assert!(initiator_rx.try_recv().is_err());
}
