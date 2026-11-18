//! JWS compact serialisation (`header.payload.signature`, base64url without padding).
//!
//! Signatures cover the transmitted bytes, never a re-serialisation, so tolerant readers and
//! newer writers agree on what was signed.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

/// The only accepted algorithm.
pub const ALG_EDDSA: &str = "EdDSA";
/// `typ` of a mandate token.
pub const TYP_MANDATE: &str = "paseka-mandate+jwt";
/// `typ` of a gate-to-gate envelope.
pub const TYP_ENVELOPE: &str = "paseka-envelope+jwt";
/// Upper bound on a compact token, so parsing is bounded.
pub const MAX_TOKEN_BYTES: usize = 256 * 1024;

/// Protected header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Signature algorithm; MUST be [`ALG_EDDSA`].
    pub alg: String,
    /// Token type; MUST match the expected use.
    pub typ: String,
    /// Key id of the signer.
    pub kid: String,
}

/// A malformed compact token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwsError {
    /// Too large.
    TooLarge,
    /// Not three dot-separated parts.
    Shape,
    /// A part is not base64url.
    Base64,
    /// Header or payload is not the expected JSON.
    Json,
}

impl std::fmt::Display for JwsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "token too large",
            Self::Shape => "token is not header.payload.signature",
            Self::Base64 => "token part is not base64url",
            Self::Json => "token header or payload is not valid JSON",
        })
    }
}

impl std::error::Error for JwsError {}

/// A split, decoded compact token. The signature is not checked here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compact {
    /// Decoded protected header.
    pub header: Header,
    /// Decoded payload bytes, exactly as signed.
    pub payload: Vec<u8>,
    /// Decoded signature bytes.
    pub signature: Vec<u8>,
    /// `base64url(header) "." base64url(payload)`: the bytes the signature covers.
    pub signing_input: Vec<u8>,
}

impl Compact {
    /// Splits and decodes `token`.
    ///
    /// # Errors
    /// [`JwsError`] when the token is oversized or malformed.
    pub fn parse(token: &str) -> Result<Self, JwsError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(JwsError::TooLarge);
        }
        let mut parts = token.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JwsError::Shape);
        };
        let dec = |x: &str| URL_SAFE_NO_PAD.decode(x).map_err(|_| JwsError::Base64);
        let header = serde_json::from_slice(&dec(h)?).map_err(|_| JwsError::Json)?;
        Ok(Self {
            header,
            payload: dec(p)?,
            signature: dec(s)?,
            signing_input: token.as_bytes()[..h.len() + 1 + p.len()].to_vec(),
        })
    }
}

/// Builds the signing input for `header` and `payload`.
///
/// # Panics
/// Never: a header of three strings always serialises.
pub fn signing_input(header: &Header, payload: &[u8]) -> String {
    let h = serde_json::to_vec(header).expect("header of strings serialises");
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(h),
        URL_SAFE_NO_PAD.encode(payload)
    )
}

/// Appends `signature` to a signing input, producing the compact token.
pub fn assemble(signing_input: &str, signature: &[u8]) -> String {
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keeps_the_signed_bytes_verbatim() {
        let header = Header {
            alg: ALG_EDDSA.into(),
            typ: TYP_MANDATE.into(),
            kid: "k1".into(),
        };
        let input = signing_input(&header, br#"{"b":1,"a":2}"#);
        let token = assemble(&input, &[7u8; 64]);
        let c = Compact::parse(&token).unwrap();
        assert_eq!(c.header, header);
        assert_eq!(c.payload, br#"{"b":1,"a":2}"#);
        assert_eq!(c.signing_input, input.as_bytes());
        assert_eq!(c.signature, vec![7u8; 64]);
    }

    #[test]
    fn parse_rejects_wrong_shapes() {
        assert_eq!(Compact::parse("a.b"), Err(JwsError::Shape));
        assert_eq!(Compact::parse("a.b.c.d"), Err(JwsError::Shape));
        assert_eq!(Compact::parse("!!.b.c"), Err(JwsError::Base64));
    }
}
