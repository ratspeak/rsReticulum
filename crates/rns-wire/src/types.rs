//! Semantic newtypes for fixed-length hashes and identifiers — distinct types
//! prevent silently mixing values with different meanings at call sites.
//! Construction checks length only, not derivation, authenticity, or existence.

use core::fmt;

/// Define a newtype wrapping a fixed-size byte array.
macro_rules! hash_newtype {
    (
        $(#[$meta:meta])*
        $vis:vis struct $Name:ident([u8; $N:expr]);
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        #[repr(transparent)]
        $vis struct $Name(pub(crate) [u8; $N]);

        impl $Name {
            /// Construct from a fixed-size byte array.
            pub const fn new(bytes: [u8; $N]) -> Self {
                Self(bytes)
            }

            /// Construct from a slice, returning `None` on length mismatch.
            pub fn from_slice(slice: &[u8]) -> Option<Self> {
                if slice.len() == $N {
                    let mut arr = [0u8; $N];
                    arr.copy_from_slice(slice);
                    Some(Self(arr))
                } else {
                    None
                }
            }

            /// Borrow the underlying byte array.
            pub const fn as_bytes(&self) -> &[u8; $N] {
                &self.0
            }

            /// Consume into the underlying byte array.
            pub const fn into_bytes(self) -> [u8; $N] {
                self.0
            }

            /// Byte length of this hash type.
            pub const LEN: usize = $N;
        }

        impl From<[u8; $N]> for $Name {
            fn from(bytes: [u8; $N]) -> Self {
                Self(bytes)
            }
        }

        impl From<&[u8; $N]> for $Name {
            fn from(bytes: &[u8; $N]) -> Self {
                Self(*bytes)
            }
        }

        impl From<$Name> for [u8; $N] {
            fn from(val: $Name) -> [u8; $N] {
                val.0
            }
        }

        impl AsRef<[u8]> for $Name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl AsRef<[u8; $N]> for $Name {
            fn as_ref(&self) -> &[u8; $N] {
                &self.0
            }
        }

        impl core::ops::Deref for $Name {
            type Target = [u8; $N];
            fn deref(&self) -> &[u8; $N] {
                &self.0
            }
        }

        impl fmt::Display for $Name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in &self.0 {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
        }

        impl core::borrow::Borrow<[u8; $N]> for $Name {
            fn borrow(&self) -> &[u8; $N] {
                &self.0
            }
        }

        impl fmt::Debug for $Name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Abbreviated for log readability: `TypeName(aabb..eeff)`.
                write!(f, "{}(", stringify!($Name))?;
                if $N <= 4 {
                    for byte in &self.0 {
                        write!(f, "{:02x}", byte)?;
                    }
                } else {
                    for byte in &self.0[..2] {
                        write!(f, "{:02x}", byte)?;
                    }
                    write!(f, "..")?;
                    for byte in &self.0[$N-2..] {
                        write!(f, "{:02x}", byte)?;
                    }
                }
                write!(f, ")")
            }
        }
    };
}

hash_newtype! {
    /// Destination hash. Identity-bound destinations use
    /// `SHA-256(name_hash || identity_hash)[..16]`; Plain destinations use
    /// `SHA-256(name_hash)[..16]`.
    pub struct DestHash([u8; 16]);
}

hash_newtype! {
    /// Link identifier derived from the hashable Link request header and keys.
    /// See [`crate::hash::link_id_from_raw`].
    pub struct LinkId([u8; 16]);
}

hash_newtype! {
    /// Next-hop transport node's identity hash, carried in Header2 packets.
    pub struct TransportId([u8; 16]);
}

hash_newtype! {
    /// Truncated hash of an identity's public keys.
    pub struct IdentityHash([u8; 16]);
}

hash_newtype! {
    /// 16-byte packet hash used for duplicate detection and receipt lookup.
    pub struct TruncatedHash([u8; 16]);
}

hash_newtype! {
    /// Full 32-byte SHA-256 packet hash.
    pub struct FullHash([u8; 32]);
}

hash_newtype! {
    /// LXMF protocol message ID, used for tracking and receipts. Obtain it
    /// from the LXMF message API: its hashable bytes exclude the signature,
    /// so hashing the complete wire image does not produce this ID.
    pub struct MessageHash([u8; 32]);
}

hash_newtype! {
    /// 10-byte hash of an application name plus aspects.
    pub struct NameHash([u8; 10]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};

    #[test]
    fn test_dest_hash_creation() {
        let bytes = [0xAA; 16];
        let hash = DestHash::new(bytes);
        assert_eq!(*hash.as_bytes(), bytes);
        assert_eq!(hash.into_bytes(), bytes);
    }

    #[test]
    fn test_from_slice() {
        let bytes = vec![0xBB; 16];
        let hash = DestHash::from_slice(&bytes).unwrap();
        assert_eq!(hash.0, [0xBB; 16]);

        assert!(DestHash::from_slice(&[0; 15]).is_none());
        assert!(DestHash::from_slice(&[0; 17]).is_none());
    }

    #[test]
    fn test_display_hex() {
        let hash = DestHash::new([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ]);
        assert_eq!(format!("{}", hash), "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn test_debug_truncated() {
        let hash = DestHash::new([0xAA; 16]);
        let debug = format!("{:?}", hash);
        assert!(debug.starts_with("DestHash("));
        assert!(debug.contains(".."));
    }

    #[test]
    fn test_from_array() {
        let bytes = [0xCC; 16];
        let hash: DestHash = bytes.into();
        assert_eq!(*hash, bytes);
    }

    #[test]
    fn test_into_array() {
        let hash = DestHash::new([0xDD; 16]);
        let bytes: [u8; 16] = hash.into();
        assert_eq!(bytes, [0xDD; 16]);
    }

    #[test]
    fn test_deref() {
        let hash = DestHash::new([0xEE; 16]);
        assert_eq!(hash[0], 0xEE);
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_hash_map_key() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        let key = DestHash::new([0x11; 16]);
        map.insert(key, "value");
        assert_eq!(map.get(&key), Some(&"value"));
    }

    #[test]
    fn test_type_safety() {
        // DestHash and LinkId share a representation but are distinct types:
        // `dest == link` would fail to compile.
        let dest = DestHash::new([0xAA; 16]);
        let link = LinkId::new([0xAA; 16]);
        assert_eq!(dest, DestHash::new([0xAA; 16]));
        assert_eq!(link, LinkId::new([0xAA; 16]));
    }

    #[test]
    fn test_full_hash() {
        let hash = FullHash::new([0xFF; 32]);
        assert_eq!(hash.len(), 32);
        assert_eq!(FullHash::LEN, 32);
    }

    #[test]
    fn test_name_hash() {
        let hash = NameHash::new([0x55; 10]);
        assert_eq!(hash.len(), 10);
        assert_eq!(NameHash::LEN, 10);
    }

    #[test]
    fn test_default() {
        let hash = DestHash::default();
        assert_eq!(hash.0, [0; 16]);
    }
}
