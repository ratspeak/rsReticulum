//! Internal transit checks for Link-request signalling. The MTU clamp changes
//! only the unsigned request trailer, preserving the 64-byte request body and
//! Link identity. A clamp of a non-default mode is rejected; authenticated
//! proof trailers are not rewritten.
use crate::{InterfaceCapacityError, messages::InterfaceEntry};
use rns_wire::link_signalling::{
    DEFAULT_LINK_MODE, LinkSignallingError, SignallingData, parse_request_signalling,
};

/// Why a transit Link request cannot be forwarded under the checked interface
/// generations and packet-capacity budgets.
#[derive(Debug, thiserror::Error)]
pub enum LinkTransitError {
    /// Malformed or unsupported request signalling.
    #[error(transparent)]
    InvalidSignalling(#[from] LinkSignallingError),
    /// An interface cannot carry the required Link packet capacity.
    #[error(transparent)]
    Capacity(#[from] InterfaceCapacityError),
    /// Forwarding would change the raw MTU trailer of an opaque, non-default mode.
    #[error("non-default Link mode requires an unsupported transit transformation")]
    UnsupportedTransitModeTransform,
    /// The ingress or egress interface owner is no longer current.
    #[error("interface registration no longer owns this route")]
    StaleInterface,
}

/// Python's relay MTU clamp (Transport.py): strip the trailer
/// when the egress cannot upgrade, clamp to `min(next-hop, previous-hop)`
/// hardware MTU when either is below the offer, otherwise relay unchanged.
/// IFAC is not subtracted. The 64-byte request body is never touched.
pub(crate) fn attenuate_request(
    payload: &[u8],
    _ingress_id: crate::messages::InterfaceId,
    ingress: &InterfaceEntry,
    _egress_id: crate::messages::InterfaceId,
    egress: &InterfaceEntry,
) -> Result<(Vec<u8>, u8, u32), LinkTransitError> {
    let signal = parse_request_signalling(payload)?;
    if !ingress.owner.is_current() || !egress.owner.is_current() {
        return Err(LinkTransitError::StaleInterface);
    }
    let base = rns_wire::link_signalling::BASE_LINK_MTU;
    if !signal.signalling_present {
        return Ok((payload.to_vec(), DEFAULT_LINK_MODE, base));
    }
    let raw = SignallingData::unpack(&payload[64..]).expect("modern request");
    if raw.mtu == 0 {
        return Ok((payload.to_vec(), raw.mode, base));
    }
    if !egress.packet_capacity.link_mtu_upgrade {
        return Ok((payload[..64].to_vec(), DEFAULT_LINK_MODE, base));
    }
    let (nh_mtu, ph_mtu) = (egress.mtu, ingress.mtu);
    if nh_mtu >= raw.mtu && ph_mtu >= raw.mtu {
        return Ok((payload.to_vec(), raw.mode, raw.mtu));
    }
    // Link.signalling_bytes raises for any mode but the enabled default.
    if raw.mode != DEFAULT_LINK_MODE {
        return Err(LinkTransitError::UnsupportedTransitModeTransform);
    }
    let clamped = nh_mtu.min(ph_mtu);
    let mut forwarded = payload[..64].to_vec();
    forwarded.extend_from_slice(&SignallingData::new(raw.mode, clamped).pack());
    Ok((
        forwarded,
        raw.mode,
        clamped & rns_wire::link_signalling::MAX_SIGNALLED_LINK_MTU,
    ))
}

/// Python's clamp of a request to a local destination (Transport.py):
/// an offer above the receiving interface's hardware MTU, or above the base MTU
/// when that interface cannot upgrade, is lowered to it. `None` keeps the bytes.
pub(crate) fn clamp_local_request(
    payload: &[u8],
    ingress: &InterfaceEntry,
) -> Result<Option<Vec<u8>>, LinkTransitError> {
    // A malformed request is left for the destination to reject, as upstream does.
    if !parse_request_signalling(payload).is_ok_and(|signal| signal.signalling_present) {
        return Ok(None);
    }
    let raw = SignallingData::unpack(&payload[64..]).expect("modern request");
    let nh_mtu = if ingress.packet_capacity.link_mtu_upgrade {
        ingress.mtu
    } else {
        rns_wire::link_signalling::BASE_LINK_MTU
    };
    if raw.mtu == 0 || nh_mtu >= raw.mtu {
        return Ok(None);
    }
    if raw.mode != DEFAULT_LINK_MODE {
        return Err(LinkTransitError::UnsupportedTransitModeTransform);
    }
    let mut clamped = payload[..64].to_vec();
    clamped.extend_from_slice(&SignallingData::new(raw.mode, nh_mtu).pack());
    Ok(Some(clamped))
}
