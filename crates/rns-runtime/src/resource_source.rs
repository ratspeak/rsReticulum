//! Bounded-memory sources for Link Resource transfers.

use std::io::{self, Read, Seek, SeekFrom};
use std::time::Duration;

use rns_link::key_derivation::LinkKeys;
use rns_protocol::resource::{
    MAX_EFFICIENT_SIZE, MAX_RESOURCE_SIZE, MAX_SEGMENTS, OutboundResource, OutboundTransfer,
    ResourceError,
};
use sha2::{Digest, Sha256};

/// Seekable source accepted by the high-level Resource API.
pub trait ResourceSource: Read + Seek + Send {}

impl<T> ResourceSource for T where T: Read + Seek + Send {}

/// Sender options shared by byte and streaming Resource sources.
#[derive(Debug, Clone, Default)]
pub struct ResourceOptions {
    pub auto_compress: bool,
    pub metadata: Option<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceSourceError {
    #[error("resource source I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("resource source exceeds the supported {MAX_RESOURCE_SIZE}-byte limit")]
    TooLarge,
    #[error("resource metadata leaves no valid bounded segment plan")]
    TooManySegments,
    #[error("resource preparation failed: {0}")]
    Protocol(#[from] ResourceError),
}

pub(crate) struct PreparedResourceSegment {
    pub transfer: OutboundTransfer,
    pub logical_hash: [u8; 32],
    pub segment_index: usize,
    pub total_segments: usize,
    pub data_size: usize,
    pub segment_data_size: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) enum ResourcePurpose {
    #[default]
    Ordinary,
    Request([u8; 16]),
}

impl ResourcePurpose {
    fn apply(self, resource: &mut OutboundResource) {
        if let Self::Request(request_id) = self {
            resource.flags.is_request = true;
            resource.request_id = Some(request_id.to_vec());
        }
    }
}

pub(crate) enum PreparedResourceSource {
    Single {
        data: Option<Vec<u8>>,
        options: ResourceOptions,
        purpose: ResourcePurpose,
    },
    Split {
        source: Box<dyn ResourceSource>,
        options: ResourceOptions,
        purpose: ResourcePurpose,
        data_size: usize,
        metadata_wire_size: usize,
        original_hash: [u8; 32],
        total_segments: usize,
        next_segment: usize,
    },
}

impl PreparedResourceSource {
    pub(crate) fn prepare<S>(
        source: S,
        options: ResourceOptions,
    ) -> Result<Self, ResourceSourceError>
    where
        S: ResourceSource + 'static,
    {
        Self::prepare_with_purpose(source, options, ResourcePurpose::Ordinary)
    }

    pub(crate) fn prepare_request<S>(
        source: S,
        request_id: [u8; 16],
    ) -> Result<Self, ResourceSourceError>
    where
        S: ResourceSource + 'static,
    {
        Self::prepare_with_purpose(
            source,
            ResourceOptions::default(),
            ResourcePurpose::Request(request_id),
        )
    }

    fn prepare_with_purpose<S>(
        mut source: S,
        options: ResourceOptions,
        purpose: ResourcePurpose,
    ) -> Result<Self, ResourceSourceError>
    where
        S: ResourceSource + 'static,
    {
        let data_size = source.seek(SeekFrom::End(0))?;
        if data_size > MAX_RESOURCE_SIZE as u64 {
            return Err(ResourceSourceError::TooLarge);
        }
        source.seek(SeekFrom::Start(0))?;
        let data_size = data_size as usize;
        let metadata_wire_size = options
            .metadata
            .as_ref()
            .map(|metadata| 3usize.saturating_add(metadata.len()))
            .unwrap_or(0);

        if metadata_wire_size.saturating_add(data_size) <= MAX_EFFICIENT_SIZE {
            let mut data = Vec::with_capacity(data_size);
            source.read_to_end(&mut data)?;
            return Ok(Self::Single {
                data: Some(data),
                options,
                purpose,
            });
        }

        if metadata_wire_size > MAX_EFFICIENT_SIZE {
            return Err(ResourceSourceError::Protocol(
                ResourceError::MetadataTooLarge,
            ));
        }
        let first_payload_size = MAX_EFFICIENT_SIZE - metadata_wire_size;
        let first_len = data_size.min(first_payload_size);
        let remaining = data_size.saturating_sub(first_len);
        let total_segments = 1 + remaining.div_ceil(MAX_EFFICIENT_SIZE);
        if total_segments > MAX_SEGMENTS {
            return Err(ResourceSourceError::TooManySegments);
        }

        let random_hash: [u8; 4] = rns_crypto::random::random_bytes(4)
            .try_into()
            .expect("fixed random-hash length");
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        hasher.update(random_hash);
        let original_hash = hasher.finalize().into();
        source.seek(SeekFrom::Start(0))?;

        Ok(Self::Split {
            source: Box::new(source),
            options,
            purpose,
            data_size,
            metadata_wire_size,
            original_hash,
            total_segments,
            next_segment: 0,
        })
    }

    pub(crate) fn next_segment(
        &mut self,
        keys: &LinkKeys,
        rtt: Duration,
    ) -> Result<Option<PreparedResourceSegment>, ResourceSourceError> {
        let encrypt = |plaintext: &[u8]| {
            rns_link::encryption::link_encrypt(keys, plaintext)
                .unwrap_or_else(|_| plaintext.to_vec())
        };

        match self {
            Self::Single {
                data,
                options,
                purpose,
            } => {
                let Some(data) = data.take() else {
                    return Ok(None);
                };
                let data_size = data.len();
                let resource = OutboundResource::with_options(
                    data,
                    options.auto_compress,
                    options.metadata.take(),
                    None,
                    Some(&encrypt),
                )?;
                let mut resource = resource;
                purpose.apply(&mut resource);
                let logical_hash = resource.resource_hash;
                Ok(Some(PreparedResourceSegment {
                    transfer: OutboundTransfer::from_prebuilt(resource, rtt),
                    logical_hash,
                    segment_index: 1,
                    total_segments: 1,
                    data_size,
                    segment_data_size: data_size,
                }))
            }
            Self::Split {
                source,
                options,
                purpose,
                data_size,
                metadata_wire_size,
                original_hash,
                total_segments,
                next_segment,
            } => {
                if *next_segment >= *total_segments {
                    return Ok(None);
                }
                let segment_index = *next_segment + 1;
                let metadata = if segment_index == 1 {
                    options.metadata.take()
                } else {
                    None
                };
                let segment_metadata_wire_size = metadata
                    .as_ref()
                    .map(|value| 3usize.saturating_add(value.len()))
                    .unwrap_or(0);
                let payload_limit = if segment_index == 1 {
                    MAX_EFFICIENT_SIZE - segment_metadata_wire_size
                } else {
                    MAX_EFFICIENT_SIZE
                };
                let mut data = vec![0u8; payload_limit];
                let mut filled = 0;
                while filled < data.len() {
                    let read = source.read(&mut data[filled..])?;
                    if read == 0 {
                        break;
                    }
                    filled += read;
                }
                data.truncate(filled);

                let mut resource = OutboundResource::with_options(
                    data,
                    options.auto_compress,
                    metadata,
                    None,
                    Some(&encrypt),
                )?;
                purpose.apply(&mut resource);
                resource.flags.split = true;
                resource.segment_index = segment_index;
                resource.total_segments = *total_segments;
                resource.original_hash = Some(*original_hash);
                resource.advertisement_data_size = data_size.saturating_add(*metadata_wire_size);
                let segment_data_size = resource.data.len();
                *next_segment += 1;

                Ok(Some(PreparedResourceSegment {
                    transfer: OutboundTransfer::from_prebuilt(resource, rtt),
                    logical_hash: *original_hash,
                    segment_index,
                    total_segments: *total_segments,
                    data_size: *data_size,
                    segment_data_size,
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use rns_crypto::x25519::X25519PrivateKey;
    use rns_link::constants::MODE_AES256_CBC;
    use rns_link::key_derivation::LinkKeys;

    use super::*;

    fn test_keys() -> LinkKeys {
        let local = X25519PrivateKey::generate();
        let remote = X25519PrivateKey::generate();
        LinkKeys::derive(&local, &remote.public_key(), &[0xA5; 16], MODE_AES256_CBC).unwrap()
    }

    #[test]
    fn small_source_prepares_one_segment() {
        let mut prepared = PreparedResourceSource::prepare(
            Cursor::new(b"small resource".to_vec()),
            ResourceOptions::default(),
        )
        .unwrap();
        let segment = prepared
            .next_segment(&test_keys(), Duration::from_millis(100))
            .unwrap()
            .unwrap();
        assert_eq!(segment.total_segments, 1);
        assert_eq!(segment.segment_index, 1);
        assert_eq!(segment.data_size, b"small resource".len());
        assert_eq!(
            segment.logical_hash,
            segment.transfer.resource.resource_hash
        );
        assert!(
            prepared
                .next_segment(&test_keys(), Duration::from_millis(100))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn split_source_is_read_one_segment_at_a_time() {
        let data = vec![0x5A; MAX_EFFICIENT_SIZE + 17];
        let mut prepared =
            PreparedResourceSource::prepare(Cursor::new(data.clone()), ResourceOptions::default())
                .unwrap();
        let keys = test_keys();
        let first = prepared
            .next_segment(&keys, Duration::from_millis(100))
            .unwrap()
            .unwrap();
        let second = prepared
            .next_segment(&keys, Duration::from_millis(100))
            .unwrap()
            .unwrap();

        assert_eq!(first.total_segments, 2);
        assert_eq!(second.total_segments, 2);
        assert_eq!(first.logical_hash, second.logical_hash);
        assert_eq!(first.transfer.resource.segment_index, 1);
        assert_eq!(second.transfer.resource.segment_index, 2);
        assert_eq!(second.transfer.resource.data.len(), 17);
        assert_eq!(first.data_size, data.len());
        assert!(
            prepared
                .next_segment(&keys, Duration::from_millis(100))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn request_source_marks_every_segment_with_request_id() {
        let request_id = [0x42; 16];
        let data = vec![0xA5; MAX_EFFICIENT_SIZE + 17];
        let mut prepared =
            PreparedResourceSource::prepare_request(Cursor::new(data), request_id).unwrap();
        let keys = test_keys();

        for expected_segment in 1..=2 {
            let segment = prepared
                .next_segment(&keys, Duration::from_millis(100))
                .unwrap()
                .unwrap();
            assert_eq!(segment.segment_index, expected_segment);
            assert!(segment.transfer.resource.flags.is_request);
            assert!(!segment.transfer.resource.flags.is_response);
            assert_eq!(
                segment.transfer.resource.request_id.as_deref(),
                Some(request_id.as_slice())
            );
        }
    }
}
