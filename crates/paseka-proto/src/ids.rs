//! Identifiers, key ids, nonces and digests (PROTOCOL §2). Each type validates its format on
//! construction and on deserialisation.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A rejected identifier or digest string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidId {
    /// Name of the identifier type.
    pub kind: &'static str,
}

impl fmt::Display for InvalidId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}", self.kind)
    }
}

impl std::error::Error for InvalidId {}

macro_rules! string_id {
    ($(#[$doc:meta])* $name:ident, $kind:literal, $valid:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates and wraps `s`.
            ///
            /// # Errors
            /// [`InvalidId`] when `s` does not have the format of this identifier.
            pub fn new(s: impl Into<String>) -> Result<Self, InvalidId> {
                let s = s.into();
                let valid: fn(&str) -> bool = $valid;
                if !valid(&s) {
                    return Err(InvalidId { kind: $kind });
                }
                Ok(Self(s))
            }

            /// The identifier as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = InvalidId;
            fn try_from(s: String) -> Result<Self, InvalidId> {
                Self::new(s)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

fn crockford(b: u8) -> bool {
    b.is_ascii_digit() || (b.is_ascii_uppercase() && !matches!(b, b'I' | b'L' | b'O' | b'U'))
}

fn ulid_with(prefix: &str, s: &str) -> bool {
    s.strip_prefix(prefix)
        .is_some_and(|rest| rest.len() == 26 && rest.bytes().all(crockford))
}

fn b64u(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn handle(s: &str, max: usize) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

string_id!(
    /// Tenant id: `t_` + ULID. Gate-local and opaque.
    TenantId,
    "tenant id",
    |s| ulid_with("t_", s)
);
string_id!(
    /// Draft id: `d_` + ULID.
    DraftId,
    "draft id",
    |s| ulid_with("d_", s)
);
string_id!(
    /// Approval request id: `r_` + ULID, one per approval request of a draft revision.
    RequestId,
    "request id",
    |s| ulid_with("r_", s)
);
string_id!(
    /// Inbox item id: `m_` + ULID.
    MessageId,
    "message id",
    |s| ulid_with("m_", s)
);
string_id!(
    /// Event id: `e_` + ULID, chosen by the sending gate.
    EventId,
    "event id",
    |s| ulid_with("e_", s)
);
string_id!(
    /// Thread id: `th_` + ULID, chosen by the gate that opens the thread.
    ThreadId,
    "thread id",
    |s| ulid_with("th_", s)
);
string_id!(
    /// Mandate id (`jti`): `md_` + ULID.
    MandateId,
    "mandate id",
    |s| ulid_with("md_", s)
);
string_id!(
    /// Pairing message id: `p_` + ULID.
    PairingId,
    "pairing id",
    |s| ulid_with("p_", s)
);
string_id!(
    /// Shelf id: `sh_` + ULID.
    ShelfId,
    "shelf id",
    |s| ulid_with("sh_", s)
);
string_id!(
    /// Document id: `doc_` + ULID. Opaque, issued by the gate, never a path.
    DocId,
    "doc id",
    |s| ulid_with("doc_", s)
);
string_id!(
    /// Peer handle set by the owner: `[a-z0-9][a-z0-9_-]{0,31}`.
    PeerHandle,
    "peer handle",
    |s| handle(s, 32)
);
string_id!(
    /// Template id: `[a-z0-9][a-z0-9_-]{0,63}`.
    TemplateId,
    "template id",
    |s| handle(s, 64)
);
string_id!(
    /// Key id: `ed25519:` + b64u of the 32-byte public key. A tenant's address towards peers.
    KeyId,
    "key id",
    |s| s
        .strip_prefix("ed25519:")
        .is_some_and(|k| k.len() == 43 && b64u(k))
);
string_id!(
    /// Gate-issued nonce: canonical b64u of 16 random bytes, 22 characters. Secret from the
    /// agent.
    Nonce,
    "nonce",
    |s| s.len() == 22 && b64u(s) && matches!(s.as_bytes()[21], b'A' | b'Q' | b'g' | b'w')
);

/// A SHA-256 digest; on the wire 64 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256(pub [u8; 32]);

impl Sha256 {
    /// Parses 64 lowercase hex characters.
    ///
    /// # Errors
    /// [`InvalidId`] on any other input, uppercase included.
    pub fn from_hex(s: &str) -> Result<Self, InvalidId> {
        let err = InvalidId { kind: "sha256" };
        let b = s.as_bytes();
        if b.len() != 64 {
            return Err(err);
        }
        let nib = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let mut out = [0u8; 32];
        for (i, pair) in b.chunks_exact(2).enumerate() {
            out[i] = (nib(pair[0]).ok_or(err.clone())? << 4) | nib(pair[1]).ok_or(err.clone())?;
        }
        Ok(Self(out))
    }

    /// Lowercase hex.
    pub fn to_hex(&self) -> String {
        use fmt::Write;
        self.0.iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256({})", self.to_hex())
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Sha256 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_round_trips_and_rejects_uppercase() {
        let h = Sha256([0xab; 32]);
        assert_eq!(Sha256::from_hex(&h.to_hex()), Ok(h));
        assert!(Sha256::from_hex(&h.to_hex().to_uppercase()).is_err());
        assert!(Sha256::from_hex("ab").is_err());
    }

    #[test]
    fn prefixed_ulids_reject_other_prefixes_and_alphabets() {
        assert!(DraftId::new("d_01JD0000000000000000000001").is_ok());
        for bad in [
            "t_01JD0000000000000000000001",
            "d_01JD000000000000000000000",
            "d_01JD000000000000000000000I",
            "d_01jd0000000000000000000001",
        ] {
            assert!(DraftId::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn doc_ids_are_opaque_never_paths() {
        assert!(DocId::new("doc_01JD0000000000000000000001").is_ok());
        for bad in [
            "notes/a.md",
            "../etc/passwd",
            "doc_../../etc/passwd000000000",
        ] {
            assert!(DocId::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn key_ids_and_handles_validate_on_deserialisation() {
        let k = "\"ed25519:YM6rJ7zZ2l98CigfxePpz270jIk0mSfrMRnjzMm2TXc\"";
        assert!(serde_json::from_str::<KeyId>(k).is_ok());
        assert!(
            serde_json::from_str::<KeyId>("\"YM6rJ7zZ2l98CigfxePpz270jIk0mSfrMRnjzMm2TXc\"")
                .is_err()
        );
        assert!(serde_json::from_str::<PeerHandle>("\"bob\"").is_ok());
        assert!(serde_json::from_str::<PeerHandle>("\"Bob Smith\"").is_err());
        assert!(serde_json::from_str::<Nonce>("\"AAECAwQFBgcICQoLDA0ODw\"").is_ok());
        assert!(serde_json::from_str::<Nonce>("\"short\"").is_err());
        assert!(serde_json::from_str::<Nonce>("\"AAECAwQFBgcICQoLDA0ODx\"").is_err());
    }
}
