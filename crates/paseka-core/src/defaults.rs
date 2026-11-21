//! The defaults table of PROTOCOL §14 against its machine-readable copy `contracts/defaults.json`.

use std::collections::BTreeMap;

use paseka_proto::OpenTrust;
use serde_json::{Value, json};

use crate::{draft, envelope, initdata, mandate, open, pairing, peer, pin};

const DEFAULTS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/defaults.json");

/// A value that is not an owner setting.
macro_rules! fixed {
    ($name:literal, $unit:literal, $value:path) => {
        json!({"name": $name, "unit": $unit, "default": $value, "code": [stringify!($value)]})
    };
}

/// An owner setting with a default and an inclusive range.
macro_rules! setting {
    ($name:literal, $unit:literal, $default:path, $range:path) => {
        json!({
            "name": $name, "unit": $unit, "default": $default,
            "min": *$range.start(), "max": *$range.end(),
            "code": [stringify!($default), stringify!($range)],
        })
    };
}

/// An owner setting with a default and only an upper bound.
macro_rules! capped {
    ($name:literal, $unit:literal, $default:path, $max:expr) => {
        json!({
            "name": $name, "unit": $unit, "default": $default, "max": $max,
            "code": [stringify!($default), stringify!($max)],
        })
    };
}

fn code_table() -> Vec<Value> {
    vec![
        setting!(
            "draft_lifetime",
            "s",
            draft::DRAFT_LIFETIME_DEFAULT,
            draft::DRAFT_LIFETIME_RANGE
        ),
        fixed!(
            "pending_drafts_per_tenant",
            "drafts",
            draft::PENDING_DRAFTS_PER_TENANT
        ),
        fixed!(
            "drafts_per_peer_per_hour",
            "drafts",
            draft::DRAFTS_PER_PEER_PER_HOUR
        ),
        capped!(
            "conversation_trust",
            "s",
            open::CONVERSATION_TTL_DEFAULT,
            open::max_lifetime(OpenTrust::Conversation)
        ),
        setting!(
            "prompt_ttl",
            "s",
            draft::PROMPT_TTL_DEFAULT,
            draft::PROMPT_TTL_RANGE
        ),
        setting!(
            "init_data_window",
            "s",
            initdata::INIT_DATA_WINDOW_DEFAULT,
            initdata::INIT_DATA_WINDOW_RANGE
        ),
        fixed!(
            "init_data_future_skew",
            "s",
            initdata::INIT_DATA_FUTURE_SECS
        ),
        fixed!("closed_mandate_lifetime", "s", mandate::CLOSED_TTL_SECS),
        fixed!("clock_skew", "s", envelope::SKEW_SECS),
        fixed!("envelope_window", "s", envelope::MAX_AGE_SECS),
        fixed!("retry_horizon", "s", envelope::RETRY_HORIZON_SECS),
        setting!(
            "key_grace",
            "days",
            peer::DEFAULT_GRACE_DAYS,
            peer::GRACE_DAYS
        ),
        capped!(
            "invite_lifetime",
            "s",
            pairing::INVITE_TTL_DEFAULT,
            pairing::INVITE_TTL_MAX
        ),
        fixed!("pin_failures", "entries", pin::PIN_MAX_FAILURES),
        fixed!("pin_freeze", "s", pin::PIN_FREEZE_SECS),
    ]
}

fn by_name(rows: &[Value]) -> BTreeMap<String, &Value> {
    let map: BTreeMap<String, &Value> = rows
        .iter()
        .map(|r| (r["name"].as_str().expect("row name").to_owned(), r))
        .collect();
    assert_eq!(map.len(), rows.len(), "duplicate parameter names");
    map
}

#[test]
fn the_code_constants_equal_the_defaults_file() {
    let file: Value = serde_json::from_slice(&std::fs::read(DEFAULTS_PATH).unwrap()).unwrap();
    assert_eq!(file["v"], 1);
    let file_rows = file["parameters"].as_array().expect("parameters array");
    let code_rows = code_table();
    let (in_file, in_code) = (by_name(file_rows), by_name(&code_rows));
    let mut failures = Vec::new();
    for (name, row) in &in_file {
        match in_code.get(name) {
            None => failures.push(format!("{name}: in the file, not in the code")),
            Some(code) if code != row => failures.push(format!("{name}: code {code}, file {row}")),
            Some(_) => {}
        }
    }
    for name in in_code.keys().filter(|n| !in_file.contains_key(*n)) {
        failures.push(format!("{name}: in the code, not in the file"));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
