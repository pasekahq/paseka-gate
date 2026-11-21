//! The Rust types accept every valid fixture in `contracts/fixtures/` and reject every invalid
//! one, except the writer-only rules listed in [`WRITER_ONLY`].

use std::path::{Path, PathBuf};

use paseka_proto::envelope::{Event, KeyProof, KeyReplacementProof, Receipt, WireError};
use paseka_proto::evidence::{
    OpenMandateEvidence, TelegramButtonEvidence, TelegramMiniAppEvidence,
    TelegramMiniAppPinEvidence,
};
use paseka_proto::jws::Header;
use paseka_proto::mandate::{ClosedMandate, OpenMandate};
use paseka_proto::pairing::{PairAccept, PairRequest};
use paseka_proto::tools::{
    DraftView, InboxOutput, JournalOutput, Message, PeersOutput, QueueOutput, ToolCall, ToolError,
};
use serde::de::DeserializeOwned;

/// Invalid fixtures whose rule binds writers (the gate) and is enforced in `paseka-core` or the
/// gate, not by deserialisation. Each entry: fixture path suffix and the enforcing check.
const WRITER_ONLY: &[(&str, &str)] = &[
    (
        "agent/status.output/invalid/awaiting-without-expiry.json",
        "gate writes expires_at",
    ),
    (
        "agent/status.output/invalid/blocked-without-reason.json",
        "gate writes reason",
    ),
    (
        "agent/status.output/invalid/released-without-delivery.json",
        "gate writes delivery",
    ),
    (
        "evidence/telegram-miniapp/invalid/edited-without-hash.json",
        "gate writes the edited hash",
    ),
    (
        "evidence/telegram-miniapp-pin/invalid/contains-pin.json",
        "gate never writes the PIN",
    ),
    (
        "evidence/telegram-button/invalid/level-a2.json",
        "core checks channel and level agree",
    ),
    (
        "evidence/open-mandate/invalid/counter-zero.json",
        "core counts from 1",
    ),
    (
        "mandate/closed/invalid/a0-without-open-mandate.json",
        "core::mandate::check_proof",
    ),
    (
        "mandate/closed/invalid/a1-with-open-mandate-channel.json",
        "core::mandate::check_proof",
    ),
    (
        "mandate/closed/invalid/nine-attachments.json",
        "core: attachment limit",
    ),
    (
        "mandate/open/invalid/button-channel.json",
        "core::open::check_shape",
    ),
    (
        "mandate/open/invalid/conversation-without-thread.json",
        "core::open::check_shape",
    ),
    (
        "mandate/open/invalid/empty-rate.json",
        "core::open::check_shape",
    ),
    (
        "mandate/open/invalid/signed-at-a1.json",
        "core::open::check_shape",
    ),
    (
        "mandate/open/invalid/t2-attachments-none.json",
        "core::open::check_shape",
    ),
    (
        "pairing/request/invalid/http-endpoint.json",
        "gate: endpoints MUST be https",
    ),
    (
        "wire/envelope/invalid/mandate-without-sd-jwt-tilde.json",
        "Compact::parse_sd_jwt",
    ),
    (
        "wire/receipt/invalid/status-rejected.json",
        "informational enum; maps to Unknown",
    ),
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/fixtures")
}

fn ok<T: DeserializeOwned>(b: &[u8]) -> Result<(), String> {
    serde_json::from_slice::<T>(b)
        .map(drop)
        .map_err(|e| e.to_string())
}

fn parse(schema: &str, b: &[u8]) -> Option<Result<(), String>> {
    if let Some(tool) = schema
        .strip_prefix("agent/")
        .and_then(|s| s.strip_suffix(".input"))
    {
        return Some(ToolCall::parse(tool, b).map(drop).map_err(|e| e.0));
    }
    Some(match schema {
        "agent/error" => ok::<ToolError>(b),
        "agent/inbox.output" => ok::<InboxOutput>(b),
        "agent/read.output" => ok::<Message>(b),
        "agent/queue.output" => ok::<QueueOutput>(b),
        "agent/peers.output" => ok::<PeersOutput>(b),
        "agent/journal.output" => ok::<JournalOutput>(b),
        s if s.starts_with("agent/") && s.ends_with(".output") => ok::<DraftView>(b),
        "evidence/telegram-button" => ok::<TelegramButtonEvidence>(b),
        "evidence/telegram-miniapp" => ok::<TelegramMiniAppEvidence>(b),
        "evidence/telegram-miniapp-pin" => ok::<TelegramMiniAppPinEvidence>(b),
        "evidence/open-mandate" => ok::<OpenMandateEvidence>(b),
        "mandate/closed" => ok::<ClosedMandate>(b),
        "mandate/open" => ok::<OpenMandate>(b),
        "mandate/jws-header" => ok::<Header>(b),
        "pairing/request" => ok::<PairRequest>(b),
        "pairing/accept" => ok::<PairAccept>(b),
        "wire/envelope" => Event::parse(b).map(drop).map_err(|e| e.to_string()),
        "wire/key-proof" => ok::<KeyProof>(b),
        "wire/key-replacement" => ok::<KeyReplacementProof>(b),
        "wire/receipt" => ok::<Receipt>(b),
        "wire/error" => ok::<WireError>(b),
        _ => return None,
    })
}

fn fixtures() -> Vec<(String, bool, PathBuf)> {
    let mut out = Vec::new();
    let mut stack = vec![root()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).expect("fixture dir") {
            let p = e.expect("dir entry").path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let rel = p
                .strip_prefix(root())
                .expect("under root")
                .to_string_lossy()
                .into_owned();
            let (schema, valid) = if let Some((s, _)) = rel.rsplit_once("/valid/") {
                (s, true)
            } else if let Some((s, _)) = rel.rsplit_once("/invalid/") {
                (s, false)
            } else {
                continue;
            };
            out.push((schema.to_owned(), valid, p));
        }
    }
    out.sort();
    out
}

#[test]
fn types_agree_with_contract_fixtures() {
    let mut failures = Vec::new();
    let mut checked = 0;
    for (schema, valid, path) in fixtures() {
        let bytes = std::fs::read(&path).expect("fixture bytes");
        let Some(result) = parse(&schema, &bytes) else {
            continue;
        };
        checked += 1;
        let rel = path
            .strip_prefix(root())
            .expect("under root")
            .to_string_lossy()
            .into_owned();
        let writer_only = WRITER_ONLY.iter().any(|(s, _)| rel == *s);
        match (valid, result, writer_only) {
            (true, Err(e), _) => failures.push(format!("{rel}: valid fixture rejected: {e}")),
            (false, Ok(()), false) => failures.push(format!("{rel}: invalid fixture accepted")),
            (false, Err(_), true) => {
                failures.push(format!(
                    "{rel}: rejected by types; drop it from WRITER_ONLY"
                ));
            }
            _ => {}
        }
    }
    assert!(checked > 100, "only {checked} fixtures checked");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
