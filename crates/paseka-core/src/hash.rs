//! Content digests.
//!
//! The content hash is SHA-256 of the exact UTF-8 text bytes, with no normalisation, so anyone
//! can recompute it with `sha256sum` from what the approval screen showed. Attachments are bound
//! separately by their own digests.

use paseka_proto::Sha256;
use sha2::Digest as _;

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> Sha256 {
    Sha256(sha2::Sha256::digest(bytes).into())
}

/// Digest of the exact outbound text.
pub fn content_sha256(text: &str) -> Sha256 {
    sha256(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_hash_matches_sha256sum_and_is_not_normalised() {
        assert_eq!(
            content_sha256("abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(content_sha256("caf\u{e9}"), content_sha256("cafe\u{301}"));
        assert_ne!(content_sha256("hi"), content_sha256("hi "));
    }
}
