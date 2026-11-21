//! Digests of PROTOCOL §3 and §11: content hash, release digest, approval challenge, short
//! authentication string. Content is never normalised, so anyone can recompute the content hash
//! with `sha256sum` from what the approval screen showed.

use paseka_proto::mandate::AttachmentMeta;
use paseka_proto::{Address, EventId, KeyId, Level, Nonce, RequestId, Sha256, TenantId, ThreadId};
use sha2::Digest as _;

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> Sha256 {
    Sha256(sha2::Sha256::digest(bytes).into())
}

/// SHA-256 of the exact UTF-8 body bytes.
pub fn content_sha256(body: &str) -> Sha256 {
    sha256(body.as_bytes())
}

fn frame(h: &mut sha2::Sha256, x: &[u8]) {
    let len = u32::try_from(x.len()).expect("framed fields are far below 4 GiB");
    h.update(len.to_be_bytes());
    h.update(x);
}

/// Everything the release digest binds: what leaves and where it goes.
#[derive(Debug, Clone, Copy)]
pub struct Release<'a> {
    /// Sending tenant.
    pub tenant: &'a TenantId,
    /// Sending tenant address.
    pub iss: &'a Address,
    /// Receiving tenant address.
    pub to: &'a Address,
    /// Thread.
    pub thread: &'a ThreadId,
    /// Event answered, if any.
    pub in_reply_to: Option<&'a EventId>,
    /// SHA-256 of the body.
    pub content_sha256: Sha256,
    /// Attachment metadata in order.
    pub attachments: &'a [AttachmentMeta],
}

/// Release digest (PROTOCOL §3.2).
///
/// # Panics
/// Never for valid content: at most 8 attachments.
pub fn release_digest(r: &Release<'_>) -> Sha256 {
    let mut h = sha2::Sha256::new();
    frame(&mut h, b"paseka/release/v1");
    frame(&mut h, r.tenant.as_str().as_bytes());
    frame(&mut h, r.iss.as_str().as_bytes());
    frame(&mut h, r.to.as_str().as_bytes());
    frame(&mut h, r.thread.as_str().as_bytes());
    frame(&mut h, r.in_reply_to.map_or("", EventId::as_str).as_bytes());
    h.update(r.content_sha256.0);
    let n = u32::try_from(r.attachments.len()).expect("at most 8 attachments");
    h.update(n.to_be_bytes());
    for a in r.attachments {
        frame(&mut h, a.name.as_bytes());
        frame(&mut h, a.media_type.as_bytes());
        h.update(a.size.to_be_bytes());
        h.update(a.sha256.0);
    }
    Sha256(h.finalize().into())
}

/// Approval challenge (PROTOCOL §3.3).
///
/// # Panics
/// Never for a valid [`Nonce`]: it always decodes to 16 bytes.
pub fn approval_challenge(
    tenant: &TenantId,
    request_id: &RequestId,
    release_digest: Sha256,
    nonce: &Nonce,
    level: Level,
) -> Sha256 {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(nonce.as_str())
        .expect("a nonce is b64u of 16 bytes");
    let mut h = sha2::Sha256::new();
    frame(&mut h, b"paseka/approval/v1");
    frame(&mut h, tenant.as_str().as_bytes());
    frame(&mut h, request_id.as_str().as_bytes());
    h.update(release_digest.0);
    h.update(&raw);
    frame(&mut h, level.as_str().as_bytes());
    Sha256(h.finalize().into())
}

/// Short authentication string shown to both owners at pairing (PROTOCOL §11): six digits.
pub fn sas(inviter: &KeyId, guest: &KeyId, code: &Nonce) -> String {
    let mut h = sha2::Sha256::new();
    frame(&mut h, b"paseka/sas/v1");
    frame(&mut h, inviter.as_str().as_bytes());
    frame(&mut h, guest.as_str().as_bytes());
    frame(&mut h, code.as_str().as_bytes());
    let d: [u8; 32] = h.finalize().into();
    format!(
        "{:06}",
        u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000
    )
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::testkit::vectors;

    fn s<T: serde::de::DeserializeOwned>(v: &Value) -> T {
        serde_json::from_value(v.clone()).unwrap()
    }

    #[test]
    fn content_hash_matches_sha256sum_and_is_not_normalised() {
        assert_eq!(
            content_sha256("abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(content_sha256("caf\u{e9}"), content_sha256("cafe\u{301}"));
        assert_ne!(content_sha256("hi"), content_sha256("hi "));
    }

    #[test]
    fn release_digests_match_the_protocol_vectors() {
        for v in vectors()["release_digest"].as_array().unwrap() {
            let i = &v["input"];
            let attachments: Vec<AttachmentMeta> = s(&i["attachments"]);
            let in_reply_to: Option<EventId> = s(&i["in_reply_to"]);
            let body: String = s(&i["body"]);
            let content = content_sha256(&body);
            assert_eq!(content, s::<Sha256>(&v["content_sha256"]));
            let r = Release {
                tenant: &s(&i["tenant"]),
                iss: &s(&i["iss"]),
                to: &s(&i["to"]),
                thread: &s(&i["thread"]),
                in_reply_to: in_reply_to.as_ref(),
                content_sha256: content,
                attachments: &attachments,
            };
            assert_eq!(release_digest(&r), s::<Sha256>(&v["release_digest"]));
        }
    }

    #[test]
    fn approval_challenge_and_sas_match_the_protocol_vectors() {
        let all = vectors();
        for v in all["approval_challenge"].as_array().unwrap() {
            let i = &v["input"];
            let got = approval_challenge(
                &s(&i["tenant"]),
                &s(&i["request_id"]),
                s(&i["release_digest"]),
                &s(&i["nonce"]),
                s(&i["level"]),
            );
            assert_eq!(got, s::<Sha256>(&v["challenge"]));
        }
        for v in all["sas"].as_array().unwrap() {
            let i = &v["input"];
            let got = sas(&s(&i["inviter_key"]), &s(&i["invitee_key"]), &s(&i["code"]));
            assert_eq!(got, s::<String>(&v["sas"]));
        }
    }
}
