//! Request attenuation without changing Link identity or coercing opaque modes.
use crate::{InterfaceCapacityError, messages::InterfaceEntry};
use rns_wire::link_signalling::{
    DEFAULT_LINK_MODE, LinkSignallingError, SignallingData, parse_request_signalling,
};

#[derive(Debug, thiserror::Error)]
pub enum LinkTransitError {
    #[error(transparent)]
    InvalidSignalling(#[from] LinkSignallingError),
    #[error(transparent)]
    Capacity(#[from] InterfaceCapacityError),
    #[error("non-default Link mode requires an unsupported transit transformation")]
    UnsupportedTransitModeTransform,
    #[error("interface registration no longer owns this route")]
    StaleInterface,
}

/// Attenuate only the unsigned request trailer. The 64-byte request body is
/// immutable. Proof trailers are authenticated and are never rewritten.
pub(crate) fn attenuate_request(
    payload: &[u8],
    ingress_id: crate::messages::InterfaceId,
    ingress: &InterfaceEntry,
    egress_id: crate::messages::InterfaceId,
    egress: &InterfaceEntry,
) -> Result<(Vec<u8>, u8, u32), LinkTransitError> {
    let signal = parse_request_signalling(payload)?;
    if !ingress.owner.is_current() || !egress.owner.is_current() {
        return Err(LinkTransitError::StaleInterface);
    }
    let incoming = ingress
        .packet_capacity
        .link_ceiling(ingress_id, ingress.active_ifac_bytes())?;
    let outgoing = egress
        .packet_capacity
        .link_ceiling(egress_id, egress.active_ifac_bytes())?;
    let ceiling = signal.mtu.get().min(incoming).min(outgoing);
    if signal.mode != DEFAULT_LINK_MODE {
        // Opaque cipher semantics must retain the exact original trailer. Even
        // zero normalization is a transformation we cannot make for that mode.
        let raw = SignallingData::unpack(&payload[64..]).expect("modern opaque mode");
        if raw.mtu != ceiling {
            return Err(LinkTransitError::UnsupportedTransitModeTransform);
        }
        return Ok((payload.to_vec(), signal.mode, ceiling));
    }
    let mut forwarded = payload[..64].to_vec();
    if signal.signalling_present && egress.packet_capacity.link_mtu_upgrade {
        forwarded.extend_from_slice(&SignallingData::try_new(signal.mode, ceiling)?.pack());
    }
    Ok((forwarded, signal.mode, ceiling))
}
