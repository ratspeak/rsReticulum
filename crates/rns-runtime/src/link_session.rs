//! Persistent initiator-side Reticulum Link sessions for applications.
//!
//! Unlike [`crate::link_client::LinkClient`], which opens a Link for one
//! request/response exchange, this module keeps the Link alive and exposes
//! ordinary encrypted Link packets until either peer closes the session.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rns_crypto::ed25519::Ed25519PublicKey;
use rns_identity::identity::Identity;
use rns_link::link::{CloseReason, Link, LinkAction, LinkState};
use rns_protocol::channel::{
    ChannelError, HandlerId, LinkChannel, MessageCallback, PreparedChannelData,
};
use rns_protocol::channel_message::{ChannelMessageError, MessageBase};
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{
    AnnounceRpcEntry, InterfaceId, OutboundRequest, TransportMessage, TransportQuery,
    TransportQueryResponse,
};
use tokio::sync::{mpsc, oneshot};

const COMMAND_BUFFER: usize = 64;
const EVENT_BUFFER: usize = 256;
const MAX_PENDING_REQUESTS: usize = 64;

#[derive(Debug, Clone)]
pub struct LinkSessionConfig {
    pub destination_hash: [u8; 16],
    pub remote_public_key: [u8; 64],
    pub hops: u8,
    pub establishment_timeout: Duration,
    pub client_label: String,
    pub identify: bool,
}

impl LinkSessionConfig {
    pub fn identified(
        destination_hash: [u8; 16],
        remote_public_key: [u8; 64],
        client_label: impl Into<String>,
    ) -> Self {
        Self {
            destination_hash,
            remote_public_key,
            hops: 1,
            establishment_timeout: Duration::from_secs(30),
            client_label: client_label.into(),
            identify: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSessionCloseReason {
    Local,
    Remote,
    Timeout,
    TransportUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkSessionEvent {
    Packet {
        data: Vec<u8>,
        packet_hash: [u8; 32],
    },
    PacketDelivered {
        packet_hash: [u8; 32],
    },
    RequestConcluded {
        request_id: [u8; 16],
        succeeded: bool,
    },
    Stale,
    Recovered,
    Closed {
        reason: LinkSessionCloseReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSessionPacketReceipt {
    pub link_id: [u8; 16],
    pub packet_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSessionResponse {
    pub request_id: [u8; 16],
    pub data: Vec<u8>,
    pub response_time: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSessionChannelReceipt {
    pub link_id: [u8; 16],
    pub sequence: u16,
    pub packet_hash: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum LinkSessionChannelError {
    #[error("link is not active")]
    LinkNotActive,
    #[error("transport channel is unavailable")]
    TransportUnavailable,
    #[error("channel error: {0}")]
    Channel(#[from] ChannelError),
    #[error("Link session task is no longer running")]
    SessionClosed,
}

#[derive(Debug, thiserror::Error)]
pub enum LinkSessionError {
    #[error("transport channel is unavailable")]
    TransportUnavailable,
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    #[error("destination announce did not include a public key")]
    PublicKeyUnavailable,
    #[error("link proof validation failed: {0}")]
    ProofInvalid(String),
    #[error("link establishment failed: {0}")]
    HandshakeFailed(String),
    #[error("local identity could not sign Link identification")]
    IdentificationUnavailable,
    #[error("link encryption failed")]
    LinkCrypto,
    #[error("link is not active")]
    LinkNotActive,
    #[error("payload is {actual} bytes; Link MDU is {max}")]
    PayloadTooLarge { actual: usize, max: usize },
    #[error("request is {actual} bytes; requests above Link MDU {max} require Resource transfer")]
    RequestRequiresResource { actual: usize, max: usize },
    #[error("too many Link requests are already pending")]
    TooManyPendingRequests,
    #[error("Link session task is no longer running")]
    SessionClosed,
}

enum LinkSessionCommand {
    SendPacket {
        payload: Vec<u8>,
        result_tx: oneshot::Sender<Result<LinkSessionPacketReceipt, LinkSessionError>>,
    },
    Request {
        path: String,
        data: Vec<u8>,
        timeout: Option<Duration>,
        result_tx: oneshot::Sender<Result<LinkSessionResponse, LinkSessionError>>,
    },
    Channel(LinkSessionChannelCommand),
    Close,
}

enum LinkSessionChannelCommand {
    RegisterMessageType {
        msg_type: u16,
        result_tx: oneshot::Sender<Result<(), LinkSessionChannelError>>,
    },
    RegisterSystemType {
        msg_type: u16,
        result_tx: oneshot::Sender<Result<(), LinkSessionChannelError>>,
    },
    AddMessageHandler {
        handler: MessageCallback,
        result_tx: oneshot::Sender<Result<HandlerId, LinkSessionChannelError>>,
    },
    RemoveMessageHandler {
        id: HandlerId,
        result_tx: oneshot::Sender<Result<bool, LinkSessionChannelError>>,
    },
    ClearMessageHandlers {
        result_tx: oneshot::Sender<Result<(), LinkSessionChannelError>>,
    },
    Send {
        msg_type: u16,
        payload: Vec<u8>,
        result_tx: oneshot::Sender<Result<LinkSessionChannelReceipt, LinkSessionChannelError>>,
    },
    IsReady {
        result_tx: oneshot::Sender<Result<bool, LinkSessionChannelError>>,
    },
    Shutdown {
        result_tx: oneshot::Sender<Result<(), LinkSessionChannelError>>,
    },
}

struct PendingSessionRequest {
    sent_at: Instant,
    result_tx: oneshot::Sender<Result<LinkSessionResponse, LinkSessionError>>,
}

struct SessionActorState {
    packets: HashSet<[u8; 32]>,
    requests: HashMap<[u8; 16], PendingSessionRequest>,
    channel: LinkChannel,
}

struct PackedChannelMessage {
    msg_type: u16,
    payload: Vec<u8>,
}

impl MessageBase for PackedChannelMessage {
    fn msg_type(&self) -> u16 {
        self.msg_type
    }

    fn pack(&self) -> Vec<u8> {
        self.payload.clone()
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<(), ChannelMessageError> {
        self.payload = raw.to_vec();
        Ok(())
    }
}

/// Cloneable app-facing handle for the reliable channel owned by a Link
/// session. Sequencing, proofs, retransmissions, and callbacks remain
/// serialized inside the session actor.
#[derive(Clone)]
pub struct LinkSessionChannelHandle {
    link_id: [u8; 16],
    mdu: usize,
    command_tx: mpsc::Sender<LinkSessionCommand>,
}

impl LinkSessionChannelHandle {
    pub fn link_id(&self) -> [u8; 16] {
        self.link_id
    }

    pub fn mdu(&self) -> usize {
        self.mdu
    }

    async fn invoke<T>(
        &self,
        command: impl FnOnce(
            oneshot::Sender<Result<T, LinkSessionChannelError>>,
        ) -> LinkSessionChannelCommand,
    ) -> Result<T, LinkSessionChannelError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkSessionCommand::Channel(command(result_tx)))
            .await
            .map_err(|_| LinkSessionChannelError::SessionClosed)?;
        result_rx
            .await
            .map_err(|_| LinkSessionChannelError::SessionClosed)?
    }

    pub async fn register_message_type(
        &self,
        msg_type: u16,
    ) -> Result<(), LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::RegisterMessageType {
            msg_type,
            result_tx,
        })
        .await
    }

    pub async fn register_system_type(&self, msg_type: u16) -> Result<(), LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::RegisterSystemType {
            msg_type,
            result_tx,
        })
        .await
    }

    pub async fn add_message_handler<F>(
        &self,
        handler: F,
    ) -> Result<HandlerId, LinkSessionChannelError>
    where
        F: Fn(u16, &[u8]) -> bool + Send + 'static,
    {
        self.invoke(|result_tx| LinkSessionChannelCommand::AddMessageHandler {
            handler: Box::new(handler),
            result_tx,
        })
        .await
    }

    pub async fn remove_message_handler(
        &self,
        id: HandlerId,
    ) -> Result<bool, LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::RemoveMessageHandler { id, result_tx })
            .await
    }

    pub async fn clear_message_handlers(&self) -> Result<(), LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::ClearMessageHandlers { result_tx })
            .await
    }

    pub async fn send(
        &self,
        message: &dyn MessageBase,
    ) -> Result<LinkSessionChannelReceipt, LinkSessionChannelError> {
        self.send_raw(message.msg_type(), message.pack()).await
    }

    pub async fn send_raw(
        &self,
        msg_type: u16,
        payload: impl Into<Vec<u8>>,
    ) -> Result<LinkSessionChannelReceipt, LinkSessionChannelError> {
        let payload = payload.into();
        self.invoke(|result_tx| LinkSessionChannelCommand::Send {
            msg_type,
            payload,
            result_tx,
        })
        .await
    }

    pub async fn is_ready_to_send(&self) -> Result<bool, LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::IsReady { result_tx })
            .await
    }

    pub async fn shutdown(&self) -> Result<(), LinkSessionChannelError> {
        self.invoke(|result_tx| LinkSessionChannelCommand::Shutdown { result_tx })
            .await
    }
}

#[derive(Clone)]
pub struct LinkSessionHandle {
    link_id: [u8; 16],
    mdu: usize,
    command_tx: mpsc::Sender<LinkSessionCommand>,
}

impl LinkSessionHandle {
    pub fn link_id(&self) -> [u8; 16] {
        self.link_id
    }

    pub fn mdu(&self) -> usize {
        self.mdu
    }

    pub fn channel(&self) -> LinkSessionChannelHandle {
        LinkSessionChannelHandle {
            link_id: self.link_id,
            mdu: rns_protocol::channel::Channel::channel_mdu(self.mdu),
            command_tx: self.command_tx.clone(),
        }
    }

    pub async fn send_packet(
        &self,
        payload: Vec<u8>,
    ) -> Result<LinkSessionPacketReceipt, LinkSessionError> {
        if payload.len() > self.mdu {
            return Err(LinkSessionError::PayloadTooLarge {
                actual: payload.len(),
                max: self.mdu,
            });
        }
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkSessionCommand::SendPacket { payload, result_tx })
            .await
            .map_err(|_| LinkSessionError::SessionClosed)?;
        result_rx
            .await
            .map_err(|_| LinkSessionError::SessionClosed)?
    }

    /// Send a packet-sized request and wait for its response.
    ///
    /// Requests whose encrypted representation exceeds the current Link MDU
    /// return [`LinkSessionError::RequestRequiresResource`]; Resource-backed
    /// requests are handled by the Resource API rather than silently changing
    /// transport semantics.
    pub async fn request(
        &self,
        path: &str,
        data: &[u8],
        timeout: Option<Duration>,
    ) -> Result<LinkSessionResponse, LinkSessionError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx
            .send(LinkSessionCommand::Request {
                path: path.to_string(),
                data: data.to_vec(),
                timeout,
                result_tx,
            })
            .await
            .map_err(|_| LinkSessionError::SessionClosed)?;
        result_rx
            .await
            .map_err(|_| LinkSessionError::SessionClosed)?
    }

    pub async fn close(&self) {
        let _ = self.command_tx.send(LinkSessionCommand::Close).await;
    }
}

pub struct LinkSession {
    pub handle: LinkSessionHandle,
    pub events: mpsc::Receiver<LinkSessionEvent>,
}

/// Ensures a cancelled or failed handshake cannot leave its temporary Link
/// destination registered in the transport actor. Once the session actor owns
/// cleanup, `disarm` transfers that responsibility.
struct DestinationRegistrationGuard {
    transport_tx: mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    armed: bool,
}

impl DestinationRegistrationGuard {
    fn new(transport_tx: mpsc::Sender<TransportMessage>, link_id: [u8; 16]) -> Self {
        Self {
            transport_tx,
            link_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DestinationRegistrationGuard {
    fn drop(&mut self) {
        if self.armed {
            deregister_destination(&self.transport_tx, self.link_id);
        }
    }
}

impl LinkSession {
    pub async fn connect(
        transport_tx: mpsc::Sender<TransportMessage>,
        identity: Identity,
        config: LinkSessionConfig,
    ) -> Result<Self, LinkSessionError> {
        let (mut link, request_data) = Link::new_initiator(config.destination_hash, config.hops);
        let link_id = link.link_id;
        let (delivery_tx, mut delivery_rx) = mpsc::channel::<DestinationEvent>(EVENT_BUFFER);

        transport_tx
            .send(TransportMessage::RegisterDestination {
                hash: link_id,
                app_name: config.client_label,
                delivery_tx: Some(delivery_tx),
            })
            .await
            .map_err(|_| LinkSessionError::TransportUnavailable)?;
        let mut registration = DestinationRegistrationGuard::new(transport_tx.clone(), link_id);

        let request = build_link_request_packet(config.destination_hash, &request_data);
        if transport_tx
            .send(TransportMessage::Outbound(OutboundRequest {
                raw: request,
                destination_hash: config.destination_hash,
            }))
            .await
            .is_err()
        {
            return Err(LinkSessionError::TransportUnavailable);
        }

        let proof = match tokio::time::timeout(
            config.establishment_timeout,
            wait_for_link_proof(&mut delivery_rx, link_id),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(LinkSessionError::Timeout("link proof")),
        };
        let (proof, attached_interface) = match proof {
            Ok(proof) => proof,
            Err(error) => return Err(error),
        };

        let peer_signing_key: [u8; 32] = config.remote_public_key[32..]
            .try_into()
            .map_err(|_| LinkSessionError::ProofInvalid("invalid public-key length".into()))?;
        let verify_key = Ed25519PublicKey::from_bytes(&peer_signing_key)
            .map_err(|error| LinkSessionError::ProofInvalid(error.to_string()))?;
        let rtt_data = link
            .validate_proof(&proof, &verify_key, &peer_signing_key)
            .map_err(|error| LinkSessionError::ProofInvalid(format!("{error:?}")))?;

        send_raw(
            &transport_tx,
            attached_interface,
            link_id,
            build_data_packet(link_id, rns_wire::context::PacketContext::Lrrtt, &rtt_data),
        )
        .await?;

        if config.identify {
            // Let the responder activate the Link before LINKIDENTIFY arrives.
            // This mirrors the timing used by the long-lived rnsh client.
            let identify_delay =
                Duration::from_secs_f64((link.rtt_secs() * 1.1 + 0.05).clamp(0.25, 1.0));
            tokio::time::sleep(identify_delay).await;
            let public_key = identity.get_public_key();
            let identify_data = link
                .identify_with_fallible(&public_key, |message| identity.sign(message))
                .map_err(|_| LinkSessionError::IdentificationUnavailable)?;
            send_raw(
                &transport_tx,
                attached_interface,
                link_id,
                build_data_packet(
                    link_id,
                    rns_wire::context::PacketContext::LinkIdentify,
                    &identify_data,
                ),
            )
            .await?;
            // Avoid racing the first application packet ahead of identification
            // on high-latency transports.
            tokio::time::sleep(identify_delay).await;
        }

        let channel_keys = link.session_keys().ok_or(LinkSessionError::LinkCrypto)?;
        let channel =
            LinkChannel::new_encrypted_with_mdu(link_id, link.rtt_secs(), link.mdu, channel_keys);
        let (command_tx, command_rx) = mpsc::channel(COMMAND_BUFFER);
        let (event_tx, events) = mpsc::channel(EVENT_BUFFER);
        let handle = LinkSessionHandle {
            link_id,
            mdu: link.mdu,
            command_tx,
        };
        tokio::spawn(run_session_actor(
            transport_tx,
            identity,
            (link, channel),
            attached_interface,
            delivery_rx,
            command_rx,
            event_tx,
        ));
        registration.disarm();

        Ok(Self { handle, events })
    }
}

pub async fn discover_destination(
    transport_tx: &mpsc::Sender<TransportMessage>,
    destination_hash: [u8; 16],
    timeout: Duration,
) -> Result<AnnounceRpcEntry, LinkSessionError> {
    if let Some(entry) = lookup_destination(transport_tx, destination_hash).await? {
        if entry.public_key.is_some() {
            return Ok(entry);
        }
    }

    rns_transport::await_path::await_path(transport_tx, destination_hash, timeout)
        .await
        .map_err(|_| LinkSessionError::Timeout("destination path"))?;
    let entry = lookup_destination(transport_tx, destination_hash)
        .await?
        .ok_or(LinkSessionError::PublicKeyUnavailable)?;
    if entry.public_key.is_none() {
        return Err(LinkSessionError::PublicKeyUnavailable);
    }
    Ok(entry)
}

pub async fn lookup_destination(
    transport_tx: &mpsc::Sender<TransportMessage>,
    destination_hash: [u8; 16],
) -> Result<Option<AnnounceRpcEntry>, LinkSessionError> {
    let (response_tx, response_rx) = oneshot::channel();
    transport_tx
        .send(TransportMessage::Rpc {
            query: TransportQuery::GetRecentAnnounces,
            response_tx,
        })
        .await
        .map_err(|_| LinkSessionError::TransportUnavailable)?;
    let response = response_rx
        .await
        .map_err(|_| LinkSessionError::TransportUnavailable)?;
    let TransportQueryResponse::Announces(entries) = response else {
        return Ok(None);
    };
    Ok(entries
        .into_iter()
        .find(|entry| entry.dest_hash == destination_hash))
}

async fn run_session_actor(
    transport_tx: mpsc::Sender<TransportMessage>,
    identity: Identity,
    link_and_channel: (Link, LinkChannel),
    attached_interface: InterfaceId,
    mut delivery_rx: mpsc::Receiver<DestinationEvent>,
    mut command_rx: mpsc::Receiver<LinkSessionCommand>,
    event_tx: mpsc::Sender<LinkSessionEvent>,
) {
    let (mut link, channel) = link_and_channel;
    let link_id = link.link_id;
    let mut state = SessionActorState {
        packets: HashSet::new(),
        requests: HashMap::new(),
        channel,
    };
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let close_reason = loop {
        tokio::select! {
            command = command_rx.recv() => {
                match command {
                    Some(LinkSessionCommand::SendPacket { payload, result_tx }) => {
                        let result = send_application_packet(
                            &transport_tx,
                            attached_interface,
                            &mut link,
                            &mut state.packets,
                            payload,
                        ).await;
                        let transport_failed = matches!(result, Err(LinkSessionError::TransportUnavailable));
                        let _ = result_tx.send(result);
                        if transport_failed {
                            break LinkSessionCloseReason::TransportUnavailable;
                        }
                    }
                    Some(LinkSessionCommand::Request {
                        path,
                        data,
                        timeout,
                        result_tx,
                    }) => {
                        if state.requests.len() >= MAX_PENDING_REQUESTS {
                            let _ = result_tx.send(Err(LinkSessionError::TooManyPendingRequests));
                            continue;
                        }
                        match send_link_request(
                            &transport_tx,
                            attached_interface,
                            &mut link,
                            &path,
                            &data,
                            timeout,
                        ).await {
                            Ok(request_id) => {
                                state.requests.insert(
                                    request_id,
                                    PendingSessionRequest {
                                        sent_at: Instant::now(),
                                        result_tx,
                                    },
                                );
                            }
                            Err(error) => {
                                let transport_failed =
                                    matches!(error, LinkSessionError::TransportUnavailable);
                                let _ = result_tx.send(Err(error));
                                if transport_failed {
                                    break LinkSessionCloseReason::TransportUnavailable;
                                }
                            }
                        }
                    }
                    Some(LinkSessionCommand::Channel(command)) => {
                        let transport_failed = handle_channel_command(
                            &transport_tx,
                            attached_interface,
                            &mut link,
                            &mut state.channel,
                            command,
                        ).await;
                        if transport_failed {
                            break LinkSessionCloseReason::TransportUnavailable;
                        }
                    }
                    Some(LinkSessionCommand::Close) | None => {
                        send_local_teardown(&transport_tx, attached_interface, &mut link).await;
                        break LinkSessionCloseReason::Local;
                    }
                }
            }
            event = delivery_rx.recv() => {
                let Some(event) = event else {
                    break LinkSessionCloseReason::TransportUnavailable;
                };
                match process_destination_event(
                    &transport_tx,
                    attached_interface,
                    &identity,
                    &mut link,
                    &mut state,
                    &event_tx,
                    event,
                ).await {
                    Ok(Some(reason)) => break reason,
                    Ok(None) => {}
                    Err(_) => break LinkSessionCloseReason::TransportUnavailable,
                }
            }
            _ = ticker.tick() => {
                state.channel.update_rtt(link.rtt_secs());
                if let Err(error) = resend_timed_out_channel_messages(
                    &transport_tx,
                    attached_interface,
                    &mut link,
                    &mut state.channel,
                ).await {
                    match error {
                        LinkSessionChannelError::Channel(ChannelError::MaxRetriesExceeded) => {
                            send_local_teardown(&transport_tx, attached_interface, &mut link).await;
                            break LinkSessionCloseReason::Timeout;
                        }
                        _ => break LinkSessionCloseReason::TransportUnavailable,
                    }
                }
                let action = link.tick();
                reap_concluded_requests(&link, &mut state.requests, &event_tx);
                match action {
                    LinkAction::SendKeepalive => {
                        if send_keepalive(&transport_tx, attached_interface, &mut link)
                            .await
                            .is_err()
                        {
                            break LinkSessionCloseReason::TransportUnavailable;
                        }
                    }
                    LinkAction::TransitionedToStale => {
                        let _ = event_tx.send(LinkSessionEvent::Stale).await;
                        if send_keepalive(&transport_tx, attached_interface, &mut link)
                            .await
                            .is_err()
                        {
                            break LinkSessionCloseReason::TransportUnavailable;
                        }
                    }
                    LinkAction::SendTeardownAndClose(data) => {
                        let _ = send_raw(
                            &transport_tx,
                            attached_interface,
                            link_id,
                            build_data_packet(link_id, rns_wire::context::PacketContext::LinkClose, &data),
                        ).await;
                        break LinkSessionCloseReason::Timeout;
                    }
                    LinkAction::Closed(_) => break LinkSessionCloseReason::Timeout,
                    LinkAction::None => {}
                }
            }
        }
    };

    state.channel.shutdown();
    fail_pending_requests(&mut state.requests, &event_tx);
    deregister_destination(&transport_tx, link_id);
    let _ = event_tx
        .send(LinkSessionEvent::Closed {
            reason: close_reason,
        })
        .await;
}

async fn handle_channel_command(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    channel: &mut LinkChannel,
    command: LinkSessionChannelCommand,
) -> bool {
    match command {
        LinkSessionChannelCommand::RegisterMessageType {
            msg_type,
            result_tx,
        } => {
            let _ = result_tx.send(
                channel
                    .register_message_type(msg_type)
                    .map_err(LinkSessionChannelError::from),
            );
        }
        LinkSessionChannelCommand::RegisterSystemType {
            msg_type,
            result_tx,
        } => {
            channel.register_system_type(msg_type);
            let _ = result_tx.send(Ok(()));
        }
        LinkSessionChannelCommand::AddMessageHandler { handler, result_tx } => {
            let _ = result_tx.send(Ok(channel.add_message_handler(handler)));
        }
        LinkSessionChannelCommand::RemoveMessageHandler { id, result_tx } => {
            let _ = result_tx.send(Ok(channel.remove_message_handler(id)));
        }
        LinkSessionChannelCommand::ClearMessageHandlers { result_tx } => {
            channel.clear_message_handlers();
            let _ = result_tx.send(Ok(()));
        }
        LinkSessionChannelCommand::Send {
            msg_type,
            payload,
            result_tx,
        } => {
            let result = send_channel_message(
                transport_tx,
                attached_interface,
                link,
                channel,
                PackedChannelMessage { msg_type, payload },
            )
            .await;
            let transport_failed =
                matches!(result, Err(LinkSessionChannelError::TransportUnavailable));
            let _ = result_tx.send(result);
            return transport_failed;
        }
        LinkSessionChannelCommand::IsReady { result_tx } => {
            let ready = matches!(link.state, LinkState::Active | LinkState::Stale)
                && channel.is_ready_to_send();
            let _ = result_tx.send(Ok(ready));
        }
        LinkSessionChannelCommand::Shutdown { result_tx } => {
            channel.shutdown();
            let _ = result_tx.send(Ok(()));
        }
    }
    false
}

async fn send_channel_message(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    channel: &mut LinkChannel,
    message: PackedChannelMessage,
) -> Result<LinkSessionChannelReceipt, LinkSessionChannelError> {
    if !matches!(link.state, LinkState::Active | LinkState::Stale) {
        return Err(LinkSessionChannelError::LinkNotActive);
    }
    let prepared = channel.prepare_send_tracked(&message)?;
    send_channel_data(transport_tx, attached_interface, link, channel, prepared).await
}

async fn send_channel_data(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    channel: &mut LinkChannel,
    prepared: PreparedChannelData,
) -> Result<LinkSessionChannelReceipt, LinkSessionChannelError> {
    let raw = build_data_packet(
        link.link_id,
        rns_wire::context::PacketContext::Channel,
        &prepared.data,
    );
    let packet_hash = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
    send_raw(transport_tx, attached_interface, link.link_id, raw)
        .await
        .map_err(|_| LinkSessionChannelError::TransportUnavailable)?;
    link.record_tx(prepared.data.len());
    channel.track_outbound_packet_hash(packet_hash, prepared.sequence);
    Ok(LinkSessionChannelReceipt {
        link_id: link.link_id,
        sequence: prepared.sequence,
        packet_hash,
    })
}

async fn resend_timed_out_channel_messages(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    channel: &mut LinkChannel,
) -> Result<(), LinkSessionChannelError> {
    for sequence in channel.timed_out_sequences() {
        let Some(data) = channel.timeout(sequence)? else {
            continue;
        };
        send_channel_data(
            transport_tx,
            attached_interface,
            link,
            channel,
            PreparedChannelData { sequence, data },
        )
        .await?;
    }
    Ok(())
}

async fn send_link_request(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    path: &str,
    data: &[u8],
    timeout: Option<Duration>,
) -> Result<[u8; 16], LinkSessionError> {
    if link.state != LinkState::Active {
        return Err(LinkSessionError::LinkNotActive);
    }
    let timeout = timeout.unwrap_or_else(|| link.default_request_timeout());
    let (encrypted, initial_request_id) = link
        .request(path, Some(data), timeout)
        .map_err(|_| LinkSessionError::LinkCrypto)?;
    if encrypted.len() > link.mdu {
        link.pending_requests
            .retain(|receipt| receipt.request_id[..16] != initial_request_id);
        return Err(LinkSessionError::RequestRequiresResource {
            actual: encrypted.len(),
            max: link.mdu,
        });
    }

    let raw = build_data_packet(
        link.link_id,
        rns_wire::context::PacketContext::Request,
        &encrypted,
    );
    let request_id =
        rns_wire::hash::truncated_packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
    if !link.update_pending_request_id(&initial_request_id, request_id) {
        return Err(LinkSessionError::LinkCrypto);
    }
    if let Err(error) = send_raw(transport_tx, attached_interface, link.link_id, raw).await {
        link.pending_requests
            .retain(|receipt| receipt.request_id[..16] != request_id);
        return Err(error);
    }
    link.record_tx(encrypted.len());
    Ok(request_id)
}

fn reap_concluded_requests(
    link: &Link,
    pending_requests: &mut HashMap<[u8; 16], PendingSessionRequest>,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
) {
    let active: HashSet<[u8; 16]> = link
        .pending_requests
        .iter()
        .map(|receipt| {
            let mut request_id = [0u8; 16];
            request_id.copy_from_slice(&receipt.request_id[..16]);
            request_id
        })
        .collect();
    let concluded: Vec<[u8; 16]> = pending_requests
        .keys()
        .copied()
        .filter(|request_id| !active.contains(request_id))
        .collect();
    for request_id in concluded {
        if let Some(pending) = pending_requests.remove(&request_id) {
            let _ = pending
                .result_tx
                .send(Err(LinkSessionError::Timeout("Link request")));
            let _ = event_tx.try_send(LinkSessionEvent::RequestConcluded {
                request_id,
                succeeded: false,
            });
        }
    }
}

fn fail_pending_requests(
    pending_requests: &mut HashMap<[u8; 16], PendingSessionRequest>,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
) {
    for (request_id, pending) in pending_requests.drain() {
        let _ = pending.result_tx.send(Err(LinkSessionError::SessionClosed));
        let _ = event_tx.try_send(LinkSessionEvent::RequestConcluded {
            request_id,
            succeeded: false,
        });
    }
}

async fn send_application_packet(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
    pending_packets: &mut HashSet<[u8; 32]>,
    payload: Vec<u8>,
) -> Result<LinkSessionPacketReceipt, LinkSessionError> {
    // STALE is a recoverable Link state, not a closed transport. Application
    // traffic such as a peer heartbeat reply must still be allowed through:
    // the reply may be the packet that lets the remote side recover the Link.
    if !matches!(link.state, LinkState::Active | LinkState::Stale) {
        return Err(LinkSessionError::LinkNotActive);
    }
    if payload.len() > link.mdu {
        return Err(LinkSessionError::PayloadTooLarge {
            actual: payload.len(),
            max: link.mdu,
        });
    }
    let encrypted = link
        .encrypt(&payload)
        .map_err(|_| LinkSessionError::LinkCrypto)?;
    let raw = build_data_packet(
        link.link_id,
        rns_wire::context::PacketContext::None,
        &encrypted,
    );
    let packet_hash = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
    send_raw(transport_tx, attached_interface, link.link_id, raw).await?;
    link.record_tx(encrypted.len());
    pending_packets.insert(packet_hash);
    Ok(LinkSessionPacketReceipt {
        link_id: link.link_id,
        packet_hash,
    })
}

async fn process_destination_event(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    identity: &Identity,
    link: &mut Link,
    state: &mut SessionActorState,
    event_tx: &mpsc::Sender<LinkSessionEvent>,
    event: DestinationEvent,
) -> Result<Option<LinkSessionCloseReason>, LinkSessionError> {
    match event {
        DestinationEvent::LinkClosed { link_id } if link_id == link.link_id => {
            return Ok(Some(LinkSessionCloseReason::Remote));
        }
        DestinationEvent::InboundPacket { raw, interface_id } => {
            // Python pins an established Link to the interface that delivered
            // its proof. Accepting Link traffic from another interface would
            // both break route affinity and permit cross-interface injection.
            if interface_id != attached_interface {
                return Ok(None);
            }
            let Ok((header, data_offset)) = rns_wire::header::PacketHeader::unpack(&raw) else {
                return Ok(None);
            };
            if header.destination_hash != link.link_id || raw.len() < data_offset {
                return Ok(None);
            }
            let body = &raw[data_offset..];

            if header.flags.packet_type == rns_wire::flags::PacketType::Proof
                && matches!(
                    header.context,
                    rns_wire::context::PacketContext::None
                        | rns_wire::context::PacketContext::LinkProof
                )
            {
                if body.len() >= 32 {
                    let mut packet_hash = [0u8; 32];
                    packet_hash.copy_from_slice(&body[..32]);
                    if link.validate_packet_proof(&packet_hash, body) {
                        let delivered_packet = state.packets.remove(&packet_hash);
                        let delivered_channel = if delivered_packet {
                            false
                        } else {
                            state
                                .channel
                                .delivered_by_packet_hash(&packet_hash, link.rtt_secs())
                                .is_some()
                        };
                        if delivered_packet || delivered_channel {
                            link.record_inbound();
                            link.keepalive.record_proof();
                        }
                        if delivered_packet {
                            let _ = event_tx
                                .send(LinkSessionEvent::PacketDelivered { packet_hash })
                                .await;
                        }
                    }
                }
                return Ok(None);
            }

            if header.flags.packet_type != rns_wire::flags::PacketType::Data {
                return Ok(None);
            }

            let was_stale = link.state == LinkState::Stale;
            match header.context {
                rns_wire::context::PacketContext::Keepalive => {
                    link.record_inbound();
                    link.record_rx(body.len());
                }
                rns_wire::context::PacketContext::LinkClose => {
                    link.record_rx(body.len());
                    if link.receive_teardown(body) {
                        return Ok(Some(LinkSessionCloseReason::Remote));
                    }
                }
                rns_wire::context::PacketContext::Lrrtt => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    let _ = link.update_rtt_from_packet(body);
                }
                rns_wire::context::PacketContext::Response => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    if let Ok((request_id, data)) = link.handle_response(body)
                        && let Some(request) = state.requests.remove(&request_id)
                    {
                        let response = LinkSessionResponse {
                            request_id,
                            data,
                            response_time: request.sent_at.elapsed(),
                        };
                        let _ = request.result_tx.send(Ok(response));
                        let _ = event_tx.try_send(LinkSessionEvent::RequestConcluded {
                            request_id,
                            succeeded: true,
                        });
                    }
                }
                rns_wire::context::PacketContext::None => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    let Ok(plaintext) = link.decrypt(body) else {
                        return Ok(None);
                    };
                    let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);
                    send_packet_proof(
                        transport_tx,
                        attached_interface,
                        identity,
                        link,
                        &packet_hash,
                    )
                    .await?;
                    event_tx
                        .send(LinkSessionEvent::Packet {
                            data: plaintext,
                            packet_hash,
                        })
                        .await
                        .map_err(|_| LinkSessionError::SessionClosed)?;
                }
                rns_wire::context::PacketContext::Channel => {
                    link.record_inbound();
                    link.record_rx(body.len());
                    let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);
                    send_packet_proof(
                        transport_tx,
                        attached_interface,
                        identity,
                        link,
                        &packet_hash,
                    )
                    .await?;
                    let _ = state.channel.receive_data(body);
                }
                _ => {}
            }
            if was_stale && link.state == LinkState::Active {
                let _ = event_tx.send(LinkSessionEvent::Recovered).await;
            }
        }
        _ => {}
    }
    Ok(None)
}

async fn send_packet_proof(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    identity: &Identity,
    link: &mut Link,
    packet_hash: &[u8; 32],
) -> Result<(), LinkSessionError> {
    let Ok(proof) = link.prove_packet_with_fallible(packet_hash, |hash| identity.sign(hash)) else {
        return Ok(());
    };
    let proof_raw = build_proof_packet(
        link.link_id,
        rns_wire::context::PacketContext::LinkProof,
        &proof,
    );
    send_raw(transport_tx, attached_interface, link.link_id, proof_raw).await?;
    link.record_tx(proof.len());
    Ok(())
}

async fn wait_for_link_proof(
    delivery_rx: &mut mpsc::Receiver<DestinationEvent>,
    link_id: [u8; 16],
) -> Result<(Vec<u8>, InterfaceId), LinkSessionError> {
    while let Some(event) = delivery_rx.recv().await {
        match event {
            DestinationEvent::LinkClosed { link_id: closed } if closed == link_id => {
                return Err(LinkSessionError::HandshakeFailed("Link closed".into()));
            }
            DestinationEvent::InboundPacket { raw, interface_id } => {
                let Ok((header, data_offset)) = rns_wire::header::PacketHeader::unpack(&raw) else {
                    continue;
                };
                if header.destination_hash == link_id
                    && header.flags.packet_type == rns_wire::flags::PacketType::Proof
                    && raw.len() > data_offset
                {
                    return Ok((raw[data_offset..].to_vec(), interface_id));
                }
            }
            _ => {}
        }
    }
    Err(LinkSessionError::HandshakeFailed(
        "destination event stream closed".into(),
    ))
}

async fn send_keepalive(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
) -> Result<(), LinkSessionError> {
    let raw = build_data_packet(
        link.link_id,
        rns_wire::context::PacketContext::Keepalive,
        &[rns_link::constants::KEEPALIVE_REQUEST],
    );
    send_raw(transport_tx, attached_interface, link.link_id, raw).await?;
    link.record_tx_keepalive(1);
    Ok(())
}

async fn send_local_teardown(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    link: &mut Link,
) {
    let link_id = link.link_id;
    let Some(data) = link.teardown(CloseReason::InitiatorClosed) else {
        return;
    };
    let _ = send_raw(
        transport_tx,
        attached_interface,
        link_id,
        build_data_packet(link_id, rns_wire::context::PacketContext::LinkClose, &data),
    )
    .await;
}

async fn send_raw(
    transport_tx: &mpsc::Sender<TransportMessage>,
    attached_interface: InterfaceId,
    destination_hash: [u8; 16],
    raw: Bytes,
) -> Result<(), LinkSessionError> {
    transport_tx
        .send(TransportMessage::OutboundAttached {
            request: OutboundRequest {
                raw,
                destination_hash,
            },
            interface_id: attached_interface,
        })
        .await
        .map_err(|_| LinkSessionError::TransportUnavailable)
}

fn deregister_destination(transport_tx: &mpsc::Sender<TransportMessage>, link_id: [u8; 16]) {
    let message = TransportMessage::DeregisterDestination { hash: link_id };
    match transport_tx.try_send(message) {
        Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
        Err(mpsc::error::TrySendError::Full(message)) => {
            // Cleanup must not be lost merely because the transport actor is
            // momentarily busy. Handshake guards can call this from Drop, so
            // enqueue asynchronously instead of blocking the current task.
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let transport_tx = transport_tx.clone();
                runtime.spawn(async move {
                    let _ = transport_tx.send(message).await;
                });
            }
        }
    }
}

fn build_link_request_packet(destination_hash: [u8; 16], request_data: &[u8]) -> Bytes {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::LinkRequest,
        },
        hops: 0,
        transport_id: None,
        destination_hash,
        context: rns_wire::context::PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(request_data);
    Bytes::from(raw)
}

fn build_data_packet(
    link_id: [u8; 16],
    context: rns_wire::context::PacketContext,
    body: &[u8],
) -> Bytes {
    build_packet(link_id, rns_wire::flags::PacketType::Data, context, body)
}

fn build_proof_packet(
    link_id: [u8; 16],
    context: rns_wire::context::PacketContext,
    body: &[u8],
) -> Bytes {
    build_packet(link_id, rns_wire::flags::PacketType::Proof, context, body)
}

fn build_packet(
    link_id: [u8; 16],
    packet_type: rns_wire::flags::PacketType,
    context: rns_wire::context::PacketContext,
    body: &[u8],
) -> Bytes {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type,
        },
        hops: 0,
        transport_id: None,
        destination_hash: link_id,
        context,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(body);
    Bytes::from(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::ed25519::Ed25519PrivateKey;

    #[test]
    fn application_packets_use_link_destination_and_none_context() {
        let link_id = [0xAB; 16];
        let packet = build_data_packet(link_id, rns_wire::context::PacketContext::None, &[1, 2, 3]);
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&packet).unwrap();
        assert_eq!(header.destination_hash, link_id);
        assert_eq!(
            header.flags.destination_type,
            rns_wire::flags::DestinationType::Link
        );
        assert_eq!(header.flags.packet_type, rns_wire::flags::PacketType::Data);
        assert_eq!(header.context, rns_wire::context::PacketContext::None);
        assert_eq!(&packet[offset..], &[1, 2, 3]);
    }

    #[tokio::test]
    async fn application_packets_can_answer_while_link_is_stale() {
        let destination_hash = [0xBC; 16];
        let server_signing = Ed25519PrivateKey::generate();
        let server_public = server_signing.public_key();
        let (mut initiator, request_data) = Link::new_initiator(destination_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &server_signing, destination_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &server_public, &server_public.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();
        initiator.state = LinkState::Stale;

        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let mut pending_packets = HashSet::new();
        let receipt = send_application_packet(
            &transport_tx,
            7,
            &mut initiator,
            &mut pending_packets,
            b"pong".to_vec(),
        )
        .await
        .expect("a stale Link must still be able to answer its peer");

        let sent = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 7,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&sent.raw).unwrap();
        assert_eq!(header.destination_hash, initiator.link_id);
        assert_eq!(responder.decrypt(&sent.raw[offset..]).unwrap(), b"pong");
        assert_eq!(
            receipt.packet_hash,
            rns_wire::hash::packet_hash(&sent.raw, header.flags.header_type)
        );
    }

    #[tokio::test]
    async fn oversized_request_requires_resource_without_leaking_a_receipt() {
        let destination_hash = [0xBE; 16];
        let server_signing = Ed25519PrivateKey::generate();
        let server_public = server_signing.public_key();
        let (mut initiator, request_data) = Link::new_initiator(destination_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &server_signing, destination_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &server_public, &server_public.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();
        let mdu = initiator.mdu;
        let payload = vec![0u8; mdu];
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);

        assert!(matches!(
            send_link_request(
                &transport_tx,
                1,
                &mut initiator,
                "/large",
                &payload,
                Some(Duration::from_secs(1)),
            )
            .await,
            Err(LinkSessionError::RequestRequiresResource { actual, max })
                if actual > max && max == mdu
        ));
        assert!(initiator.pending_requests.is_empty());
        assert!(transport_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn session_actor_recovers_and_answers_data_received_after_stale() {
        let destination_hash = [0xBD; 16];
        let server_signing = Ed25519PrivateKey::generate();
        let server_public = server_signing.public_key();
        let client_identity = Identity::new();
        let (mut initiator, request_data) = Link::new_initiator(destination_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &server_signing, destination_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &server_public, &server_public.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();

        // Make the actor enter STALE on its first tick. The subsequent inbound
        // application packet models a peer heartbeat arriving during the
        // recoverable stale grace period.
        initiator.keepalive.stale_time = Duration::ZERO;
        initiator.keepalive.keepalive_interval = Duration::from_secs(60);

        let link_id = initiator.link_id;
        let mdu = initiator.mdu;
        let channel = LinkChannel::new_encrypted_with_mdu(
            link_id,
            initiator.rtt_secs(),
            mdu,
            initiator.session_keys().unwrap(),
        );
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(16);
        let (delivery_tx, delivery_rx) = mpsc::channel::<DestinationEvent>(16);
        let (command_tx, command_rx) = mpsc::channel::<LinkSessionCommand>(16);
        let (event_tx, mut event_rx) = mpsc::channel::<LinkSessionEvent>(16);
        let handle = LinkSessionHandle {
            link_id,
            mdu,
            command_tx,
        };

        tokio::spawn(run_session_actor(
            transport_tx,
            client_identity,
            (initiator, channel),
            7,
            delivery_rx,
            command_rx,
            event_tx,
        ));

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
                .await
                .unwrap(),
            Some(LinkSessionEvent::Stale)
        );
        let stale_keepalive = transport_rx.recv().await.unwrap();
        assert!(matches!(
            stale_keepalive,
            TransportMessage::OutboundAttached {
                interface_id: 7,
                ..
            }
        ));

        let inbound_ciphertext = responder.encrypt(b"ping").unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_data_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::None,
                    &inbound_ciphertext,
                ),
                interface_id: 7,
            })
            .await
            .unwrap();

        let inbound_proof = transport_rx.recv().await.unwrap();
        assert!(matches!(
            inbound_proof,
            TransportMessage::OutboundAttached {
                interface_id: 7,
                ..
            }
        ));
        assert!(matches!(
            event_rx.recv().await,
            Some(LinkSessionEvent::Packet { ref data, .. }) if data == b"ping"
        ));
        assert_eq!(event_rx.recv().await, Some(LinkSessionEvent::Recovered));

        handle
            .send_packet(b"pong".to_vec())
            .await
            .expect("the recovered actor must accept the heartbeat response");
        let response = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 7,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (_, offset) = rns_wire::header::PacketHeader::unpack(&response.raw).unwrap();
        assert_eq!(responder.decrypt(&response.raw[offset..]).unwrap(), b"pong");

        handle.close().await;
    }

    #[tokio::test]
    async fn cancelled_handshake_deregisters_temporary_link_destination() {
        let destination_hash = [0x33; 16];
        let remote_identity = Identity::new();
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(8);

        let connect = tokio::spawn(LinkSession::connect(
            transport_tx,
            Identity::new(),
            LinkSessionConfig {
                destination_hash,
                remote_public_key: remote_identity.get_public_key(),
                hops: 1,
                establishment_timeout: Duration::from_secs(30),
                client_label: "test.cancelled-link-session".into(),
                identify: false,
            },
        ));

        let link_id = match transport_rx.recv().await.unwrap() {
            TransportMessage::RegisterDestination { hash, .. } => hash,
            other => panic!("unexpected transport message: {other:?}"),
        };
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::Outbound(_))
        ));

        connect.abort();
        assert!(matches!(connect.await, Err(error) if error.is_cancelled()));
        match tokio::time::timeout(Duration::from_secs(1), transport_rx.recv())
            .await
            .expect("deregistration timeout")
            .expect("transport channel closed")
        {
            TransportMessage::DeregisterDestination { hash } => assert_eq!(hash, link_id),
            other => panic!("unexpected transport message: {other:?}"),
        }
    }

    #[tokio::test]
    async fn persistent_session_identifies_and_exchanges_link_packets() {
        let destination_hash = [0x44; 16];
        let server_identity = Identity::new();
        let server_public = server_identity.get_public_key();
        let server_signing = server_identity.get_signing_key().unwrap();
        let client_identity = Identity::new();
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(64);

        let connect = tokio::spawn(LinkSession::connect(
            transport_tx.clone(),
            client_identity.clone(),
            LinkSessionConfig {
                destination_hash,
                remote_public_key: server_public,
                hops: 1,
                establishment_timeout: Duration::from_secs(2),
                client_label: "test.link-session".into(),
                identify: true,
            },
        ));

        let delivery_tx = match transport_rx.recv().await.unwrap() {
            TransportMessage::RegisterDestination {
                hash,
                delivery_tx: Some(tx),
                ..
            } => {
                assert_ne!(hash, destination_hash);
                tx
            }
            other => panic!("unexpected transport message: {other:?}"),
        };

        let request = match transport_rx.recv().await.unwrap() {
            TransportMessage::Outbound(request) => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (request_header, request_offset) =
            rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            request_header.flags.packet_type,
            rns_wire::flags::PacketType::LinkRequest
        );
        let (mut responder, proof) = Link::new_responder(
            &request.raw[request_offset..],
            &server_signing,
            destination_hash,
            1,
        )
        .unwrap();
        let proof_packet = build_proof_packet(
            responder.link_id,
            rns_wire::context::PacketContext::None,
            &proof,
        );
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: proof_packet,
                interface_id: 1,
            })
            .await
            .unwrap();

        let rtt = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (rtt_header, rtt_offset) = rns_wire::header::PacketHeader::unpack(&rtt.raw).unwrap();
        assert_eq!(rtt_header.context, rns_wire::context::PacketContext::Lrrtt);
        responder
            .receive_rtt_packet(&rtt.raw[rtt_offset..])
            .unwrap();

        let identify = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (identify_header, identify_offset) =
            rns_wire::header::PacketHeader::unpack(&identify.raw).unwrap();
        assert_eq!(
            identify_header.context,
            rns_wire::context::PacketContext::LinkIdentify
        );
        let identified = responder
            .handle_identification(&identify.raw[identify_offset..])
            .unwrap();
        assert_eq!(identified, client_identity.get_public_key());

        let mut session = connect.await.unwrap().unwrap();
        let receipt = session
            .handle
            .send_packet(b"hello hub".to_vec())
            .await
            .unwrap();
        let sent = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (sent_header, sent_offset) = rns_wire::header::PacketHeader::unpack(&sent.raw).unwrap();
        assert_eq!(sent_header.context, rns_wire::context::PacketContext::None);
        assert_eq!(
            responder.decrypt(&sent.raw[sent_offset..]).unwrap(),
            b"hello hub"
        );
        assert_eq!(
            receipt.packet_hash,
            rns_wire::hash::packet_hash(&sent.raw, sent_header.flags.header_type)
        );

        let request_handle = session.handle.clone();
        let request_task = tokio::spawn(async move {
            request_handle
                .request("/echo", b"request body", Some(Duration::from_secs(2)))
                .await
        });
        let request = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (request_header, request_offset) =
            rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            request_header.context,
            rns_wire::context::PacketContext::Request
        );
        let (_packed_id, path_hash, _timestamp, request_data) = responder
            .handle_request(&request.raw[request_offset..])
            .unwrap();
        assert_eq!(path_hash, rns_crypto::sha::truncated_hash(b"/echo"));
        assert_eq!(request_data, b"request body");
        let request_id =
            rns_wire::hash::truncated_packet_hash(&request.raw, request_header.flags.header_type);
        let response = responder
            .create_response(&request_id, b"response body")
            .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_data_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::Response,
                    &response,
                ),
                interface_id: 1,
            })
            .await
            .unwrap();
        let response = request_task.await.unwrap().unwrap();
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.data, b"response body");
        assert!(matches!(
            session.events.recv().await,
            Some(LinkSessionEvent::RequestConcluded {
                request_id: concluded,
                succeeded: true,
            }) if concluded == request_id
        ));

        let timeout_handle = session.handle.clone();
        let timeout_task = tokio::spawn(async move {
            timeout_handle
                .request("/timeout", b"", Some(Duration::ZERO))
                .await
        });
        let timed_out_request = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (timed_out_header, _) =
            rns_wire::header::PacketHeader::unpack(&timed_out_request.raw).unwrap();
        let timed_out_id = rns_wire::hash::truncated_packet_hash(
            &timed_out_request.raw,
            timed_out_header.flags.header_type,
        );
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), timeout_task)
                .await
                .expect("request timeout result")
                .unwrap(),
            Err(LinkSessionError::Timeout("Link request"))
        ));
        assert!(matches!(
            session.events.recv().await,
            Some(LinkSessionEvent::RequestConcluded {
                request_id: concluded,
                succeeded: false,
            }) if concluded == timed_out_id
        ));

        let channel = session.handle.channel();
        assert_eq!(
            channel.mdu(),
            rns_protocol::channel::Channel::channel_mdu(session.handle.mdu())
        );
        channel.register_message_type(0x0042).await.unwrap();
        let (message_tx_guard, mut message_rx) = mpsc::unbounded_channel();
        let message_tx = message_tx_guard.clone();
        let handler_id = channel
            .add_message_handler(move |msg_type, payload| {
                let _ = message_tx.send((msg_type, payload.to_vec()));
                true
            })
            .await
            .unwrap();
        let mut responder_channel = LinkChannel::new_encrypted_with_mdu(
            responder.link_id,
            responder.rtt_secs(),
            responder.mdu,
            responder.session_keys().unwrap(),
        );
        responder_channel.register_message_type(0x0042).unwrap();

        let first_receipt = channel
            .send_raw(0x0042, b"first channel frame")
            .await
            .unwrap();
        let first_channel_packet = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (first_channel_header, first_channel_offset) =
            rns_wire::header::PacketHeader::unpack(&first_channel_packet.raw).unwrap();
        assert_eq!(
            first_channel_header.context,
            rns_wire::context::PacketContext::Channel
        );
        assert_eq!(
            responder_channel
                .receive_data(&first_channel_packet.raw[first_channel_offset..])
                .unwrap(),
            vec![(0x0042, b"first channel frame".to_vec())]
        );

        let _second_receipt = channel
            .send_raw(0x0042, b"second channel frame")
            .await
            .unwrap();
        let second_channel_packet = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (_, second_channel_offset) =
            rns_wire::header::PacketHeader::unpack(&second_channel_packet.raw).unwrap();
        assert_eq!(
            responder_channel
                .receive_data(&second_channel_packet.raw[second_channel_offset..])
                .unwrap(),
            vec![(0x0042, b"second channel frame".to_vec())]
        );
        assert!(!channel.is_ready_to_send().await.unwrap());

        let first_proof = responder
            .prove_packet_with_fallible(&first_receipt.packet_hash, |hash| {
                server_identity.sign(hash)
            })
            .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_proof_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::LinkProof,
                    &first_proof,
                ),
                interface_id: 1,
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if channel.is_ready_to_send().await.unwrap() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("channel proof should reopen the send window");

        let inbound_prepared = responder_channel
            .prepare_send_tracked(&PackedChannelMessage {
                msg_type: 0x0042,
                payload: b"inbound channel frame".to_vec(),
            })
            .unwrap();
        let inbound_channel_packet = build_data_packet(
            responder.link_id,
            rns_wire::context::PacketContext::Channel,
            &inbound_prepared.data,
        );
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: inbound_channel_packet,
                interface_id: 1,
            })
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), message_rx.recv())
                .await
                .unwrap(),
            Some((0x0042, b"inbound channel frame".to_vec()))
        );
        let inbound_proof = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (inbound_proof_header, _) =
            rns_wire::header::PacketHeader::unpack(&inbound_proof.raw).unwrap();
        assert_eq!(
            inbound_proof_header.flags.packet_type,
            rns_wire::flags::PacketType::Proof
        );

        assert!(channel.remove_message_handler(handler_id).await.unwrap());
        let ignored_prepared = responder_channel
            .prepare_send_tracked(&PackedChannelMessage {
                msg_type: 0x0042,
                payload: b"ignored after removal".to_vec(),
            })
            .unwrap();
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: build_data_packet(
                    responder.link_id,
                    rns_wire::context::PacketContext::Channel,
                    &ignored_prepared.data,
                ),
                interface_id: 1,
            })
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), message_rx.recv())
                .await
                .is_err()
        );
        let _ignored_proof = transport_rx.recv().await.unwrap();

        let inbound_ciphertext = responder.encrypt(b"hello client").unwrap();
        let inbound = build_data_packet(
            responder.link_id,
            rns_wire::context::PacketContext::None,
            &inbound_ciphertext,
        );
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: inbound.clone(),
                interface_id: 9,
            })
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), session.events.recv())
                .await
                .is_err(),
            "Link traffic from a different interface must be ignored"
        );
        assert!(
            transport_rx.try_recv().is_err(),
            "off-interface Link traffic must not be proved"
        );
        delivery_tx
            .send(DestinationEvent::InboundPacket {
                raw: inbound,
                interface_id: 1,
            })
            .await
            .unwrap();
        let event = session.events.recv().await.unwrap();
        assert!(matches!(
            event,
            LinkSessionEvent::Packet { ref data, .. } if data == b"hello client"
        ));
        let proof = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (proof_header, _) = rns_wire::header::PacketHeader::unpack(&proof.raw).unwrap();
        assert_eq!(
            proof_header.flags.packet_type,
            rns_wire::flags::PacketType::Proof
        );
        assert_eq!(
            proof_header.context,
            rns_wire::context::PacketContext::LinkProof
        );

        session.handle.close().await;
        let close = match transport_rx.recv().await.unwrap() {
            TransportMessage::OutboundAttached {
                request,
                interface_id: 1,
            } => request,
            other => panic!("unexpected transport message: {other:?}"),
        };
        let (close_header, close_offset) =
            rns_wire::header::PacketHeader::unpack(&close.raw).unwrap();
        assert_eq!(
            close_header.context,
            rns_wire::context::PacketContext::LinkClose
        );
        assert!(responder.receive_teardown(&close.raw[close_offset..]));
        assert_eq!(
            session.events.recv().await,
            Some(LinkSessionEvent::Closed {
                reason: LinkSessionCloseReason::Local
            })
        );
    }
}
