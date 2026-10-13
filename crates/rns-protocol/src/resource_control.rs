//! Checked admission for fixed-stride Resource control frames.
//! A decoder profile is not a promise that the transport can carry a control.
use crate::resource::{
    MAPHASH_LEN, MAX_EFFICIENT_SIZE, MAX_RESOURCE_SIZE, MAX_SEGMENTS, RANDOM_HASH_SIZE,
    ResourceError, ResourceFlags, SDU, WINDOW_MAX,
};
use crate::resource_adv::ResourceAdvertisement;
use rns_wire::context::PacketContext;

/// Pinned Python Resource hashmap stride. Never derive it from a small custom MTU.
pub const HASHMAP_STRIDE: usize = 74;

/// CBC token framing used by Link encryption, with checked arithmetic.
pub fn encrypted_len(plaintext_len: usize) -> Result<usize, ResourceError> {
    plaintext_len
        .checked_div(16)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_mul(16))
        .and_then(|n| n.checked_add(48))
        .ok_or(ResourceError::TooLarge)
}

/// Check the actual Reticulum packet length before encryption or state admission.
pub fn check_control_frame(
    context: PacketContext,
    payload_len: usize,
    encrypted: bool,
    header_len: usize,
    mtu: usize,
) -> Result<(), ResourceError> {
    let body = if encrypted {
        encrypted_len(payload_len)?
    } else {
        payload_len
    };
    let encoded_len = header_len
        .checked_add(body)
        .ok_or(ResourceError::TooLarge)?;
    if encoded_len > mtu {
        return Err(ResourceError::ControlFrameTooLarge {
            context,
            encoded_len,
            mtu,
        });
    }
    Ok(())
}

/// Check one already-described advertisement without allocating its encoded body.
pub fn check_advertisement(
    advertisement: &ResourceAdvertisement,
    mtu: usize,
) -> Result<(), ResourceError> {
    check_control_frame(
        PacketContext::ResourceAdv,
        advertisement.encoded_len()?,
        true,
        rns_wire::constants::HEADER_MINSIZE,
        mtu,
    )
}

/// Preflight the largest control shapes across all segments, before copying the
/// source, allocating parts/hashmaps, reserving a transfer, or invoking encryption.
/// Compression only shrinks the admitted upper bound. The 74-hash stride stays
/// fixed. Request identifiers are borrowed here, including their real length.
pub fn preflight_outbound(
    data_len: usize,
    metadata_len: Option<usize>,
    request_id: Option<&[u8]>,
    is_response: bool,
    encrypted: bool,
    mtu: usize,
) -> Result<(), ResourceError> {
    preflight_outbound_with_sdu(
        data_len,
        metadata_len,
        request_id,
        is_response,
        encrypted,
        SDU,
        mtu,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn preflight_outbound_with_sdu(
    data_len: usize,
    metadata_len: Option<usize>,
    request_id: Option<&[u8]>,
    is_response: bool,
    encrypted: bool,
    part_sdu: usize,
    mtu: usize,
) -> Result<(), ResourceError> {
    if part_sdu == 0 {
        return Err(ResourceError::InvalidAdvertisement);
    }
    if data_len > MAX_RESOURCE_SIZE {
        return Err(ResourceError::TooLarge);
    }
    let metadata_wire = metadata_len
        .map(|n| n.checked_add(3).ok_or(ResourceError::MetadataTooLarge))
        .transpose()?
        .unwrap_or(0);
    if metadata_wire > MAX_EFFICIENT_SIZE {
        return Err(ResourceError::MetadataTooLarge);
    }
    let total_data = data_len
        .checked_add(metadata_wire)
        .ok_or(ResourceError::TooLarge)?;
    let first = data_len.min(MAX_EFFICIENT_SIZE - metadata_wire);
    let total_segments = 1usize
        .checked_add(data_len.saturating_sub(first).div_ceil(MAX_EFFICIENT_SIZE))
        .ok_or(ResourceError::TooLarge)?;
    if total_segments > MAX_SEGMENTS {
        return Err(ResourceError::TooLarge);
    }
    // Request ID storage is bounded by the packet before copying into the small
    // temporary advertisement. No attacker-sized allocation precedes admission.
    if let Some(id) = request_id {
        check_control_frame(
            PacketContext::ResourceAdv,
            id.len(),
            true,
            rns_wire::constants::HEADER_MINSIZE,
            mtu,
        )?;
    }
    let segment_len = total_data.min(MAX_EFFICIENT_SIZE);
    let blob = segment_len
        .checked_add(RANDOM_HASH_SIZE)
        .ok_or(ResourceError::TooLarge)?;
    let transfer_size = if encrypted {
        encrypted_len(blob)?
    } else {
        blob
    };
    let parts = transfer_size.div_ceil(part_sdu);
    let hashes = [[0u8; MAPHASH_LEN]; HASHMAP_STRIDE];
    let mut advertisement = ResourceAdvertisement::new(
        transfer_size,
        total_data,
        parts,
        [0; 32],
        vec![0; RANDOM_HASH_SIZE],
        ResourceFlags {
            encrypted,
            compressed: false,
            split: total_segments > 1,
            is_request: request_id.is_some() && !is_response,
            is_response,
            has_metadata: metadata_len.is_some(),
        },
        &hashes[..parts.min(HASHMAP_STRIDE)],
        rns_wire::constants::LINK_MDU,
    );
    advertisement.segment_index = total_segments;
    advertisement.total_segments = total_segments;
    advertisement.request_id = request_id.map(<[u8]>::to_vec);
    check_advertisement(&advertisement, mtu)?;
    // HMU uses the production MessagePack encoder and largest possible segment
    // index for this admitted source. At most 296 hashmap octets are materialized.
    let max_map_segment = parts.saturating_sub(1) / HASHMAP_STRIDE;
    let hmu = encode_hashmap_update(
        &[0; 32],
        max_map_segment,
        &[0; HASHMAP_STRIDE * MAPHASH_LEN],
    );
    check_control_frame(
        PacketContext::ResourceHmu,
        hmu.len(),
        true,
        rns_wire::constants::HEADER_MINSIZE,
        mtu,
    )?;
    // Exhaustion marker + last map hash + resource hash + maximum request window.
    check_control_frame(
        PacketContext::ResourceReq,
        1 + MAPHASH_LEN + 32 + WINDOW_MAX * MAPHASH_LEN,
        true,
        rns_wire::constants::HEADER_MINSIZE,
        mtu,
    )?;
    check_control_frame(
        PacketContext::ResourcePrf,
        64,
        false,
        rns_wire::constants::HEADER_MINSIZE,
        mtu,
    )?;
    check_control_frame(
        PacketContext::ResourceIcl,
        32,
        true,
        rns_wire::constants::HEADER_MINSIZE,
        mtu,
    )
}

/// Shared HMU encoder used by size admission and real transmission.
pub fn encode_hashmap_update(resource_hash: &[u8; 32], segment: usize, hashes: &[u8]) -> Vec<u8> {
    use rmpv::Value;
    let value = Value::Array(vec![
        Value::Integer((segment as u64).into()),
        Value::Binary(hashes.to_vec()),
    ]);
    let mut output = resource_hash.to_vec();
    rmpv::encode::write_value(&mut output, &value).expect("Vec MessagePack write");
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    fn advertisement(request_id: Option<Vec<u8>>) -> ResourceAdvertisement {
        let mut adv = ResourceAdvertisement::new(
            1_048_640,
            1_048_575,
            2260,
            [1; 32],
            vec![2; 4],
            ResourceFlags {
                encrypted: true,
                compressed: false,
                split: false,
                is_request: request_id.is_some(),
                is_response: false,
                has_metadata: false,
            },
            &[[3; 4]; 74],
            rns_wire::constants::LINK_MDU,
        );
        adv.request_id = request_id;
        adv
    }
    #[test]
    fn control_preflight_shared_advertisement_encoder_matches_retained_wire() {
        use rmpv::Value;
        for id in [None, Some(vec![7; 16])] {
            let a = advertisement(id);
            let pairs = vec![
                ("t", Value::from(a.transfer_size as u64)),
                ("d", Value::from(a.data_size as u64)),
                ("n", Value::from(a.num_parts as u64)),
                ("h", Value::Binary(a.resource_hash.to_vec())),
                ("r", Value::Binary(a.random_hash.clone())),
                ("o", Value::Binary(a.original_hash.to_vec())),
                ("i", Value::from(a.segment_index as u64)),
                ("l", Value::from(a.total_segments as u64)),
                (
                    "q",
                    a.request_id
                        .clone()
                        .map(Value::Binary)
                        .unwrap_or(Value::Nil),
                ),
                ("f", Value::from(a.flags.to_byte())),
                ("m", Value::Binary(a.hashmap.clone())),
            ];
            let old = Value::Map(
                pairs
                    .into_iter()
                    .map(|(k, v)| (Value::from(k), v))
                    .collect(),
            );
            let mut expected = Vec::new();
            rmpv::encode::write_value(&mut expected, &old).unwrap();
            assert_eq!(a.pack(), expected);
            assert_eq!(a.encoded_len().unwrap(), expected.len());
            assert!(check_advertisement(&a, 500).is_ok());
        }
        let a = advertisement(Some(vec![7; 16]));
        let exact = 19 + encrypted_len(a.encoded_len().unwrap()).unwrap();
        assert_eq!(exact, 499);
        assert!(check_advertisement(&a, 499).is_ok());
        assert!(matches!(
            check_advertisement(&a, 498),
            Err(ResourceError::ControlFrameTooLarge {
                encoded_len: 499,
                ..
            })
        ));
    }
    #[test]
    fn control_preflight_extreme_metadata_shape_uses_no_large_source() {
        let mut a = advertisement(Some(vec![7; 16]));
        a.data_size = 1 << 30;
        a.segment_index = 1024;
        a.total_segments = 1025;
        a.flags.split = true;
        assert!(matches!(
            check_advertisement(&a, 500),
            Err(ResourceError::ControlFrameTooLarge { .. })
        ));
        assert!(matches!(
            preflight_outbound(0, None, Some(&[7; 500]), false, true, 500),
            Err(ResourceError::ControlFrameTooLarge { .. })
        ));
        assert!(matches!(
            encrypted_len(usize::MAX),
            Err(ResourceError::TooLarge)
        ));
    }
    #[test]
    fn control_preflight_preserves_stride_and_refuses_before_encrypt_or_parts() {
        assert_eq!(
            HASHMAP_STRIDE,
            crate::resource_adv::hashmap_max_len(rns_wire::constants::LINK_MDU)
        );
        preflight_outbound(75 * SDU, None, None, false, true, 500).unwrap();
        preflight_outbound(MAX_EFFICIENT_SIZE, None, Some(&[0; 16]), false, true, 500).unwrap();
        let called = std::cell::Cell::new(false);
        let encrypt = |_: &[u8]| {
            called.set(true);
            Vec::new()
        };
        let result = crate::resource::OutboundResource::with_options(
            vec![0; 32],
            false,
            None,
            Some(0),
            Some(&encrypt),
        );
        assert!(matches!(result, Err(ResourceError::InvalidAdvertisement)));
        assert!(!called.get());
    }
    #[test]
    fn control_preflight_late_metadata_mutation_cannot_enter_advertised() {
        let mut transfer = crate::resource::OutboundTransfer::new(
            vec![0; 16],
            false,
            std::time::Duration::from_millis(10),
        )
        .unwrap();
        transfer.resource.request_id = Some(vec![0; 500]);
        assert!(matches!(
            transfer.tick(),
            crate::resource::TransferAction::Failed(_)
        ));
        assert_eq!(
            transfer.resource.state,
            crate::resource::ResourceState::Failed
        );
        assert!(matches!(
            transfer.tick(),
            crate::resource::TransferAction::Failed(_)
        ));
        assert!(ResourceAdvertisement::unpack(&vec![0; 500]).is_err());
    }
}
