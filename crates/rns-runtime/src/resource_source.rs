//! Seekable sources for Link Resource transfers, prepared one segment at a
//! time for large inputs. The source must satisfy the stability contract in
//! [`ResourceSource`]; custom reader allocations are outside this memory bound.

use std::io::{self, Read, Seek, SeekFrom};
use std::time::Duration;

use rns_link::key_derivation::LinkKeys;
use rns_protocol::resource::{
    MAX_EFFICIENT_SIZE, MAX_RESOURCE_SIZE, OutboundResource, OutboundTransfer, ResourceError,
};
use sha2::{Digest, Sha256};

/// Seekable source accepted by the high-level Resource API.
///
/// Keep contents and length stable throughout preparation and transfer. The
/// runtime seeks to the end to measure length, rewinds to zero, and may read
/// the entire source to hash it before reading segments again. It does not
/// snapshot or lock a file against concurrent writers. `Read` and `Seek` are
/// synchronous; implementations must return finite, consistent data.
pub trait ResourceSource: Read + Seek + Send {}

impl<T> ResourceSource for T where T: Read + Seek + Send {}

/// Sender options shared by byte and streaming Resource sources.
#[derive(Debug, Clone, Default)]
pub struct ResourceOptions {
    pub auto_compress: bool,
    pub metadata: Option<Vec<u8>>,
}

/// Compression policy for request and response Resources, as Resource's
/// `auto_compress` option: a bool, or an int byte limit that enables
/// compression only for data no larger than the limit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AutoCompress {
    Off,
    /// Compress data up to Resource.AUTO_COMPRESS_MAX_SIZE.
    #[default]
    On,
    /// Compress data no larger than this many bytes.
    Limit(usize),
}

impl AutoCompress {
    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Whether data of `data_size` bytes is compressed under this policy.
    pub fn applies_to(self, data_size: usize) -> bool {
        match self {
            Self::Off => false,
            Self::On => data_size <= rns_protocol::compression::AUTO_COMPRESS_MAX_SIZE,
            Self::Limit(limit) => data_size <= limit,
        }
    }
}

impl From<bool> for AutoCompress {
    fn from(value: bool) -> Self {
        if value { Self::On } else { Self::Off }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceSourceError {
    #[error("resource source I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("resource source size does not fit in memory addresses on this platform")]
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
    Response([u8; 16]),
}

impl ResourcePurpose {
    fn apply(self, resource: &mut OutboundResource) {
        match self {
            Self::Ordinary => {}
            Self::Request(request_id) => {
                resource.flags.is_request = true;
                resource.request_id = Some(request_id.to_vec());
            }
            Self::Response(request_id) => {
                resource.flags.is_response = true;
                resource.request_id = Some(request_id.to_vec());
            }
        }
    }

    fn request_id(&self) -> Option<&[u8]> {
        match self {
            Self::Ordinary => None,
            Self::Request(id) | Self::Response(id) => Some(id.as_slice()),
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
        Self::prepare_with_purpose(source, options, None, ResourcePurpose::Ordinary)
    }

    /// Request bodies use Resource's default `auto_compress=True`.
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
            Some(AutoCompress::On),
            ResourcePurpose::Request(request_id),
        )
    }

    /// A response Resource correlated with `request_id`, as Link.handle_request
    /// sends a file response. Compression is judged against the whole source
    /// size, as Resource does for file input.
    pub(crate) fn prepare_response<S>(
        source: S,
        request_id: [u8; 16],
        metadata: Option<Vec<u8>>,
        auto_compress: AutoCompress,
    ) -> Result<Self, ResourceSourceError>
    where
        S: ResourceSource + 'static,
    {
        Self::prepare_with_purpose(
            source,
            ResourceOptions {
                auto_compress: false,
                metadata,
            },
            Some(auto_compress),
            ResourcePurpose::Response(request_id),
        )
    }

    /// Whether every segment has been produced.
    pub(crate) fn is_exhausted(&self) -> bool {
        match self {
            Self::Single { data, .. } => data.is_none(),
            Self::Split {
                total_segments,
                next_segment,
                ..
            } => next_segment >= total_segments,
        }
    }

    fn prepare_with_purpose<S>(
        source: S,
        mut options: ResourceOptions,
        auto_compress: Option<AutoCompress>,
        purpose: ResourcePurpose,
    ) -> Result<Self, ResourceSourceError>
    where
        S: ResourceSource + 'static,
    {
        let mut source: Box<dyn ResourceSource> = Box::new(source);
        let data_size = match source.seek(SeekFrom::End(0)) {
            Ok(0) => {
                source.seek(SeekFrom::Start(0))?;
                source = proxy_stream(source)?;
                source.seek(SeekFrom::End(0))?
            }
            Ok(size) => size,
            // Pipes and procfs files cannot report a length (ESPIPE, EINVAL).
            Err(_) => {
                source = proxy_stream(source)?;
                source.seek(SeekFrom::End(0))?
            }
        };
        let data_size = usize::try_from(data_size).map_err(|_| ResourceSourceError::TooLarge)?;
        source.seek(SeekFrom::Start(0))?;
        match auto_compress {
            Some(policy) => options.auto_compress = policy.applies_to(data_size),
            None => options.auto_compress &= AutoCompress::On.applies_to(data_size),
        }
        let metadata_wire_size = options
            .metadata
            .as_ref()
            .map(|metadata| 3usize.saturating_add(metadata.len()))
            .unwrap_or(0);

        rns_protocol::resource_control::preflight_outbound(
            data_size,
            options.metadata.as_ref().map(Vec::len),
            purpose.request_id(),
            matches!(purpose, ResourcePurpose::Response(_)),
            true,
            rns_wire::constants::MTU,
        )?;

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
            source,
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
        link_sdu: usize,
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
                    Some(link_sdu),
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
                    Some(link_sdu),
                    Some(&encrypt),
                )?;
                purpose.apply(&mut resource);
                resource.flags.split = true;
                // Later segments advertise the metadata flag without carrying metadata.
                resource.flags.has_metadata |= *metadata_wire_size > 0;
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

/// Copy a zero-size or unseekable source (pipe, procfs) into a temporary file,
/// as Resource proxies a zero-size reader.
fn proxy_stream(
    source: Box<dyn ResourceSource>,
) -> Result<Box<dyn ResourceSource>, ResourceSourceError> {
    let mut spool = tempfile::tempfile()?;
    let copied = io::copy(&mut source.take(MAX_RESOURCE_SIZE as u64 + 1), &mut spool)?;
    if copied > MAX_RESOURCE_SIZE as u64 {
        return Err(ResourceSourceError::TooLarge);
    }
    spool.seek(SeekFrom::Start(0))?;
    Ok(Box::new(spool))
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
    fn auto_compress_limit_follows_resource_option_types() {
        assert!(!AutoCompress::from(false).applies_to(10));
        assert!(AutoCompress::from(true).applies_to(10));
        assert!(AutoCompress::Limit(1024).applies_to(1024));
        assert!(!AutoCompress::Limit(1024).applies_to(1025));
        assert!(
            !AutoCompress::On.applies_to(rns_protocol::compression::AUTO_COMPRESS_MAX_SIZE + 1)
        );
    }

    #[test]
    fn request_source_is_compressed_by_default() {
        let mut prepared =
            PreparedResourceSource::prepare_request(Cursor::new(vec![0u8; 4096]), [7; 16]).unwrap();
        let segment = prepared
            .next_segment(
                &test_keys(),
                Duration::from_millis(100),
                rns_protocol::resource::SDU,
            )
            .unwrap()
            .unwrap();
        assert!(segment.transfer.resource.flags.compressed);
        assert!(segment.transfer.resource.flags.is_request);
    }

    #[test]
    fn small_source_prepares_one_segment() {
        let mut prepared = PreparedResourceSource::prepare(
            Cursor::new(b"small resource".to_vec()),
            ResourceOptions::default(),
        )
        .unwrap();
        let segment = prepared
            .next_segment(
                &test_keys(),
                Duration::from_millis(100),
                rns_protocol::resource::SDU,
            )
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
                .next_segment(
                    &test_keys(),
                    Duration::from_millis(100),
                    rns_protocol::resource::SDU
                )
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
            .next_segment(
                &keys,
                Duration::from_millis(100),
                rns_protocol::resource::SDU,
            )
            .unwrap()
            .unwrap();
        let second = prepared
            .next_segment(
                &keys,
                Duration::from_millis(100),
                rns_protocol::resource::SDU,
            )
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
                .next_segment(
                    &keys,
                    Duration::from_millis(100),
                    rns_protocol::resource::SDU
                )
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
                .next_segment(
                    &keys,
                    Duration::from_millis(100),
                    rns_protocol::resource::SDU,
                )
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
