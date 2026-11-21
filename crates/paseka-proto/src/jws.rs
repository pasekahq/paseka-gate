//! JWS compact serialisation and the SD-JWT form of mandates (PROTOCOL §8.1).
//!
//! Signatures cover the transmitted bytes, never a re-serialisation, so tolerant readers and
//! newer writers agree on what was signed.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::KeyId;

/// JWS `alg`: only `EdDSA` with an Ed25519 key exists; anything else is a parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Alg {
    /// `EdDSA`.
    #[default]
    EdDSA,
}

/// JWS `typ`: separates the signing domains of the one tenant key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Typ {
    /// Closed or open mandate.
    #[serde(rename = "paseka-mandate+sd-jwt")]
    Mandate,
    /// Gate-to-gate envelope.
    #[serde(rename = "paseka-envelope+jwt")]
    Envelope,
    /// Delivery receipt.
    #[serde(rename = "paseka-receipt+jwt")]
    Receipt,
    /// Pairing message.
    #[serde(rename = "paseka-pair+jwt")]
    Pair,
    /// Proof of possession of a new key in a `key.rotate` event.
    #[serde(rename = "paseka-key-proof+jwt")]
    KeyProof,
}

/// Upper bound on a compact token: the 6 MiB request limit of PROTOCOL §10.1.
pub const MAX_TOKEN_BYTES: usize = 6 * 1024 * 1024;

/// Protected header. Any other member (`crit`, `jwk`, `jku`, `x5u`, `x5c`, ...) is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    /// Signature algorithm.
    pub alg: Alg,
    /// Key id of the signer.
    pub kid: KeyId,
    /// Token type; MUST match the expected use.
    pub typ: Typ,
}

/// A malformed compact token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwsError {
    /// Too large.
    TooLarge,
    /// Not three dot-separated parts, or an SD-JWT without the single trailing `~`.
    Shape,
    /// A part is not canonical unpadded base64url.
    Base64,
    /// The header is not the expected JSON object.
    Header,
}

impl std::fmt::Display for JwsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "token too large",
            Self::Shape => "token is not header.payload.signature",
            Self::Base64 => "token part is not base64url",
            Self::Header => "token header is invalid",
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
    /// Splits and decodes a compact JWS.
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
        let header = serde_json::from_slice(&dec(h)?).map_err(|_| JwsError::Header)?;
        Ok(Self {
            header,
            payload: dec(p)?,
            signature: dec(s)?,
            signing_input: token.as_bytes()[..h.len() + 1 + p.len()].to_vec(),
        })
    }

    /// Parses an SD-JWT with zero disclosures: a compact JWS followed by exactly one `~`.
    ///
    /// # Errors
    /// [`JwsError::Shape`] without the trailing `~` or with any disclosure; else as [`Self::parse`].
    pub fn parse_sd_jwt(token: &str) -> Result<Self, JwsError> {
        match token.strip_suffix('~') {
            Some(jws) if !jws.contains('~') => Self::parse(jws),
            _ => Err(JwsError::Shape),
        }
    }
}

/// Builds the signing input for `header` and `payload`.
///
/// # Panics
/// Never: a header of enums and a string always serialises.
pub fn signing_input(header: &Header, payload: &[u8]) -> String {
    let h = serde_json::to_vec(header).expect("header serialises");
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

    fn header() -> Header {
        Header {
            alg: Alg::EdDSA,
            kid: KeyId::new("ed25519:YM6rJ7zZ2l98CigfxePpz270jIk0mSfrMRnjzMm2TXc").unwrap(),
            typ: Typ::Mandate,
        }
    }

    #[test]
    fn parse_keeps_the_signed_bytes_verbatim() {
        let input = signing_input(&header(), br#"{"b":1,"a":2}"#);
        let token = assemble(&input, &[7u8; 64]);
        let c = Compact::parse_sd_jwt(&format!("{token}~")).unwrap();
        assert_eq!(c.header, header());
        assert_eq!(c.payload, br#"{"b":1,"a":2}"#);
        assert_eq!(c.signing_input, input.as_bytes());
        assert_eq!(c.signature, vec![7u8; 64]);
    }

    #[test]
    fn parse_rejects_wrong_shapes_disclosures_and_extra_header_members() {
        assert_eq!(Compact::parse("a.b"), Err(JwsError::Shape));
        assert_eq!(Compact::parse("a.b.c.d"), Err(JwsError::Shape));
        assert_eq!(Compact::parse("!!.b.c"), Err(JwsError::Base64));
        let token = assemble(&signing_input(&header(), b"{}"), &[7u8; 64]);
        assert_eq!(Compact::parse_sd_jwt(&token), Err(JwsError::Shape));
        assert_eq!(
            Compact::parse_sd_jwt(&format!("{token}~WyJ4Il0~")),
            Err(JwsError::Shape)
        );
        let crit = r#"{"alg":"EdDSA","kid":"ed25519:YM6rJ7zZ2l98CigfxePpz270jIk0mSfrMRnjzMm2TXc","typ":"paseka-pair+jwt","crit":["b64"]}"#;
        let token = format!("{}.e30.AAAA", URL_SAFE_NO_PAD.encode(crit));
        assert_eq!(Compact::parse(&token), Err(JwsError::Header));
    }
}
