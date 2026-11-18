//! Identifier newtypes. Each validates its charset on construction and on deserialisation.

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
    ($(#[$doc:meta])* $name:ident, $kind:literal, $min:literal, $max:literal, $valid:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates and wraps `s`.
            ///
            /// # Errors
            /// [`InvalidId`] when `s` is empty, too long or has a forbidden character.
            pub fn new(s: impl Into<String>) -> Result<Self, InvalidId> {
                let s = s.into();
                let valid: fn(&str) -> bool = $valid;
                if s.len() < $min || s.len() > $max || !valid(&s) {
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

fn slug(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn b64url(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn doc_path(s: &str) -> bool {
    !s.starts_with('/')
        && !s.ends_with('/')
        && s.split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.' | b'/')
        })
}

string_id!(
    /// A tenant of a (possibly multi-tenant) gate. Every stored object carries one.
    TenantId,
    "tenant id",
    1,
    64,
    slug
);
string_id!(
    /// A paired peer as named by the local tenant.
    PeerId,
    "peer id",
    1,
    64,
    slug
);
string_id!(
    /// A remote gate: the base64url ed25519 public key of its tenant.
    GateId,
    "gate id",
    43,
    43,
    b64url
);
string_id!(
    /// An outbound draft.
    DraftId,
    "draft id",
    1,
    64,
    b64url
);
string_id!(
    /// A gate-issued single-use nonce, base64url of at least 16 random bytes.
    Nonce,
    "nonce",
    22,
    128,
    b64url
);
string_id!(
    /// A document on a shelf: a relative path of lowercase segments, no `.`/`..` segment.
    DocId,
    "doc id",
    1,
    256,
    doc_path
);

/// A SHA-256 digest; on the wire 64 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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
    fn doc_id_rejects_traversal_and_absolute_paths() {
        assert!(DocId::new("projects/paseka/readme.md").is_ok());
        for bad in [
            "../etc/passwd",
            "/etc/passwd",
            "a/../b",
            "a//b",
            "a/./b",
            "A.md",
            "a/",
        ] {
            assert!(DocId::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ids_validate_on_deserialisation() {
        assert!(serde_json::from_str::<TenantId>("\"alice\"").is_ok());
        assert!(serde_json::from_str::<TenantId>("\"Alice Smith\"").is_err());
        assert!(serde_json::from_str::<Nonce>("\"short\"").is_err());
    }
}
