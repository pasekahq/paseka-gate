//! Conformance attacks CA-n of `docs/THREAT-MODEL.md` against paseka-gate.
//!
//! Each [`Attack`] tries one way to release bytes without the owner's consent and passes when
//! the gate refuses. Attacks that need a part not built yet are [`Outcome::Pending`] with the
//! missing part, so this table stays the single checklist.

#![forbid(unsafe_code)]

mod consent;
mod policy;
mod wire;
mod world;

/// Result of one attack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The gate refused as required.
    Pass,
    /// The attack got through or was refused for the wrong reason.
    Fail(String),
    /// The attack needs a part that does not exist yet.
    Pending(&'static str),
}

/// One conformance attack.
#[derive(Debug, Clone, Copy)]
pub struct Attack {
    /// `CA-n`.
    pub id: &'static str,
    /// The security property it tests, `SP-n`.
    pub sp: &'static str,
    /// What the attacker tries.
    pub title: &'static str,
    /// Runs the attack.
    pub run: fn() -> Outcome,
}

/// Missing part: the gate daemon with storage and the agent HTTP/MCP server.
pub const NEEDS_SERVER: &str = "the gate daemon (paseka serve)";
/// Missing part: the consent bot and Mini App with initData verification.
pub const NEEDS_BOT: &str = "the consent bot and Mini App";
/// Missing part: invite codes stored and consumed by the inviter's gate.
pub const NEEDS_PAIRING: &str = "invite codes (PROTOCOL §11)";
/// Missing part: the per-tenant hash-chained journal.
pub const NEEDS_JOURNAL: &str = "the journal";
/// Missing part: an installed gate running as its own unix user.
pub const NEEDS_INSTALL: &str = "an installed gate (install skill)";

macro_rules! attacks {
    ($($id:literal $sp:literal $title:literal => $run:expr;)*) => {
        /// Every conformance attack, in CA order.
        pub const ATTACKS: &[Attack] = &[$(Attack { id: $id, sp: $sp, title: $title, run: $run }),*];
    };
}

attacks! {
    "CA-1" "SP-1" "agent tool list offers an approval, mandate or settings operation" => policy::ca01_no_approve_tool;
    "CA-2" "SP-1" "propose, revise or share with approved, proof, mandate, nonce, evidence or level" => policy::ca02_proof_like_fields;
    "CA-3" "SP-2" "free text to a T0 peer, prompt never answered" => consent::ca03_unanswered_prompt_expires;
    "CA-4" "SP-2" "forged Telegram update without or with a wrong webhook secret" => || Outcome::Pending(NEEDS_BOT);
    "CA-5" "SP-2" "evidence-shaped JSON in the journal, inbox or a draft body" => || Outcome::Pending(NEEDS_SERVER);
    "CA-6" "SP-3" "revise after the prompt, then press the old Approve button" => consent::ca06_old_button_after_revise;
    "CA-7" "SP-3" "revise or withdraw after approval" => consent::ca07_revise_or_withdraw_after_approval;
    "CA-8" "SP-3" "attachment swapped between prompt and decision" => consent::ca08_attachment_swap;
    "CA-9" "SP-3" "Mini App decision with another release digest" => consent::ca09_miniapp_digest_mismatch;
    "CA-10" "SP-4" "the same approval delivered twice" => consent::ca10_double_press;
    "CA-11" "SP-4" "Mini App decision replayed with the same initData" => || Outcome::Pending(NEEDS_BOT);
    "CA-12" "SP-4" "released envelope replayed to the peer" => wire::ca12_envelope_replay;
    "CA-13" "SP-5" "Approve pressed after the prompt TTL" => consent::ca13_press_after_ttl;
    "CA-14" "SP-5" "initData with a stale or future auth_date" => || Outcome::Pending(NEEDS_BOT);
    "CA-15" "SP-6" "a non-approver presses a forwarded prompt" => consent::ca15_non_approver;
    "CA-16" "SP-6" "initData valid by bot-token HMAC only" => || Outcome::Pending(NEEDS_BOT);
    "CA-17" "SP-6" "initData signed for another bot id" => || Outcome::Pending(NEEDS_BOT);
    "CA-18" "SP-7" "classifier says safe for free text" => policy::ca18_classifier_says_safe;
    "CA-19" "SP-7" "canary in the body, obfuscated or base64-encoded" => policy::ca19_canary_blocks;
    "CA-20" "SP-7" "owner edit adds a canary and approves" => policy::ca20_owner_edit_with_canary;
    "CA-21" "SP-7" "required level above every configured channel" => consent::ca21_level_above_every_channel;
    "CA-22" "SP-8" "agent reads detector results from tool output" => policy::ca22_no_oracle;
    "CA-23" "SP-9" "security settings edited in the config after the ceremony" => || Outcome::Pending(NEEDS_SERVER);
    "CA-24" "SP-9" "agent tool used as a side path to settings" => policy::ca24_no_settings_side_path;
    "CA-25" "SP-10" "open mandate beyond its rate, lifetime or length" => policy::ca25_open_mandate_bounds;
    "CA-26" "SP-10" "link or long number in a template field" => policy::ca26_template_field_smuggle;
    "CA-27" "SP-10" "open mandate used after revocation" => policy::ca27_revoked_mandate;
    "CA-28" "SP-10" "second open mandate while one is pending" => policy::ca28_second_open_mandate;
    "CA-29" "SP-11" "share of a doc not on an open shelf, unknown, or path-like" => policy::ca29_share_outside_shelf;
    "CA-30" "SP-11" "share note with a link, a blob or 201 characters" => policy::ca30_share_note_smuggle;
    "CA-31" "SP-12" "envelope with a bad signature, an unknown sender or key, another peer's key, alg none or wrong typ" => wire::ca31_forged_envelopes;
    "CA-32" "SP-12" "envelope from tenant A's peer addressed to tenant B" => wire::ca32_cross_tenant_envelope;
    "CA-33" "SP-13" "envelope replayed after the window, from the future, or same id other bytes" => wire::ca33_wire_windows;
    "CA-34" "SP-14" "mandate for other content, recipient, thread, lifetime, level or a reused jti" => wire::ca34_mandate_mismatch;
    "CA-35" "SP-15" "used or expired invite code" => || Outcome::Pending(NEEDS_PAIRING);
    "CA-36" "SP-15" "messages before the inviter's owner confirmed the pairing" => wire::ca36_pairing_pending;
    "CA-37" "SP-15" "pair accept signed by a key other than the one in the pair URI, or from another address" => wire::ca37_pair_accept_other_key;
    "CA-38" "SP-16" "tenant A's agent token with tenant B's ids" => || Outcome::Pending(NEEDS_SERVER);
    "CA-39" "SP-16" "approver of tenant A decides tenant B's request on a shared bot" => consent::ca39_cross_tenant_decision;
    "CA-40" "SP-17" "bidi, zero-width or control characters in the body" => policy::ca40_invisible_characters;
    "CA-41" "SP-17" "body longer than the A1 prompt capacity" => policy::ca41_over_prompt_capacity;
    "CA-42" "SP-18" "agent's unix user reads the gate state" => || Outcome::Pending(NEEDS_INSTALL);
    "CA-43" "SP-19" "agent proposes 100 drafts in a minute" => || Outcome::Pending(NEEDS_SERVER);
    "CA-44" "SP-19" "peer burst above its volume limit" => || Outcome::Pending(NEEDS_SERVER);
    "CA-45" "SP-20" "one journal row modified in the database" => || Outcome::Pending(NEEDS_JOURNAL);
    "CA-46" "SP-21" "gate killed between decision and delivery" => || Outcome::Pending(NEEDS_SERVER);
    "CA-47" "SP-7" "A1 button approval for a request that needs A2" => consent::ca47_weaker_channel;
    "CA-48" "SP-22" "key substitution: rotation proof not by new_key, recorded address re-paired with another key" => wire::ca48_key_substitution;
    "CA-49" "SP-22" "key.rotate signed by a key that is not the address's current key" => wire::ca49_rotation_not_by_current_key;
    "CA-50" "SP-22" "peer's previous key used after previous_valid_until" => wire::ca50_previous_key_after_grace;
    "CA-51" "SP-22" "holder of a stolen key moves the peer to their own key by key.rotate or key.revoke" => wire::ca51_thief_moves_peer_to_own_key;
    "CA-52" "SP-22" "peer's revoked key, or the previous key whose grace a revocation ended, used" => wire::ca52_revoked_key_used;
    "CA-53" "SP-23" "tripwire mode cleared without PIN: through A1, A2, an open mandate, a mode change or the agent" => policy::ca53_clear_tripwire_without_pin;
    "CA-54" "SP-24" "content of a Never source released by an owner approval, an open mandate or a Never lifted outside the settings" => policy::ca54_never_source_leaves;
    "CA-55" "SP-24" "agent under a conversation mandate sends content of an Ask source and of a Never source in that thread" => policy::ca55_conversation_mandate_beyond_allow;
}

/// Runs every attack.
pub fn run_all() -> Vec<(&'static Attack, Outcome)> {
    ATTACKS.iter().map(|a| (a, (a.run)())).collect()
}

/// Runs the attack `id` (`CA-n`).
pub fn run(id: &str) -> Option<Outcome> {
    ATTACKS.iter().find(|a| a.id == id).map(|a| (a.run)())
}

fn expect<T: std::fmt::Debug, E: std::fmt::Debug>(
    r: Result<T, E>,
    want: impl FnOnce(&E) -> bool,
) -> Outcome {
    match r {
        Ok(v) => Outcome::Fail(format!("accepted: {v:?}")),
        Err(e) if want(&e) => Outcome::Pass,
        Err(e) => Outcome::Fail(format!("refused for the wrong reason: {e:?}")),
    }
}

fn all(outcomes: impl IntoIterator<Item = Outcome>) -> Outcome {
    outcomes
        .into_iter()
        .find(|o| *o != Outcome::Pass)
        .unwrap_or(Outcome::Pass)
}
