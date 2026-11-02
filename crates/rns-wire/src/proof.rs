//! Body of a PROOF packet (explicit or implicit form).

use crate::constants::{EXPL_LENGTH, IMPL_LENGTH};
use alloc::vec::Vec;

/// Body of a packet-delivery proof.
///
/// These forms are distinct from a Link handshake proof. Parsing the body
/// does not verify its signature or identify the signer.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofData {
    /// 96-byte form: packet hash followed by its Ed25519 signature.
    Explicit {
        packet_hash: [u8; 32],
        signature: [u8; 64],
    },
    /// 64-byte form: signature only; the hash is known from the matching receipt.
    Implicit { signature: [u8; 64] },
}

impl ProofData {
    /// Parse a proof body, dispatching on its 96- or 64-byte length.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        match data.len() {
            EXPL_LENGTH => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data[..32]);
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&data[32..96]);
                Some(Self::Explicit {
                    packet_hash: hash,
                    signature: sig,
                })
            }
            IMPL_LENGTH => {
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&data[..64]);
                Some(Self::Implicit { signature: sig })
            }
            _ => None,
        }
    }

    /// Serialize the proof body.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Explicit {
                packet_hash,
                signature,
            } => {
                let mut out = Vec::with_capacity(EXPL_LENGTH);
                out.extend_from_slice(packet_hash);
                out.extend_from_slice(signature);
                out
            }
            Self::Implicit { signature } => signature.to_vec(),
        }
    }

    /// Signature, present in both proof forms.
    pub fn signature(&self) -> &[u8; 64] {
        match self {
            Self::Explicit { signature, .. } | Self::Implicit { signature } => signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explicit_roundtrip() {
        let proof = ProofData::Explicit {
            packet_hash: [0xAA; 32],
            signature: [0xBB; 64],
        };
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 96);
        let parsed = ProofData::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, proof);
    }

    #[test]
    fn test_implicit_roundtrip() {
        let proof = ProofData::Implicit {
            signature: [0xCC; 64],
        };
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 64);
        let parsed = ProofData::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, proof);
    }

    #[test]
    fn test_invalid_length() {
        assert!(ProofData::from_bytes(&[0u8; 50]).is_none());
    }
}
