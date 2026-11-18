//! Conformance attacks against paseka-gate.
//!
//! Each [`Attack`] tries one way to release bytes without the owner's consent and passes when
//! the gate refuses. Attacks that need a running gate (consent bot, Mini App, HTTP) are listed
//! as [`Outcome::Pending`] until the server exists, so the list stays the single checklist.

#![forbid(unsafe_code)]

mod fixture;
mod gate;
mod mandates;

/// Result of one attack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The gate refused as required.
    Pass,
    /// The gate let the attack through, or refused for the wrong reason.
    Fail(String),
    /// Not runnable yet: needs the named component.
    Pending(&'static str),
}

/// One named attack.
#[derive(Debug, Clone, Copy)]
pub struct Attack {
    /// Stable id, used as the test name and in reports.
    pub id: &'static str,
    /// What the attacker tries.
    pub title: &'static str,
    /// Runs the attack.
    pub run: fn() -> Outcome,
}

const NEEDS_SERVER: &str = "a running gate (paseka serve)";
const NEEDS_BOT: &str = "the consent bot and Mini App";

fn pending_server() -> Outcome {
    Outcome::Pending(NEEDS_SERVER)
}

fn pending_bot() -> Outcome {
    Outcome::Pending(NEEDS_BOT)
}

/// Every attack, in report order.
pub const ATTACKS: &[Attack] = &[
    Attack {
        id: "forged_mandate",
        title: "mandate signed by a key that is not an approver",
        run: mandates::forged,
    },
    Attack {
        id: "tampered_mandate",
        title: "payload edited after signing",
        run: mandates::tampered,
    },
    Attack {
        id: "alg_confusion",
        title: "header alg none or an empty signature",
        run: mandates::alg_confusion,
    },
    Attack {
        id: "expired_mandate",
        title: "mandate used after exp",
        run: mandates::expired,
    },
    Attack {
        id: "overlong_mandate",
        title: "closed mandate with a lifetime far beyond 60 s",
        run: mandates::overlong,
    },
    Attack {
        id: "replayed_mandate",
        title: "the same mandate used twice",
        run: mandates::replayed,
    },
    Attack {
        id: "stale_nonce",
        title: "nonce never issued or expired",
        run: mandates::stale_nonce,
    },
    Attack {
        id: "preview_swap",
        title: "owner approved text A, agent releases text B",
        run: mandates::preview_swap,
    },
    Attack {
        id: "recipient_swap",
        title: "mandate for bob used for carol",
        run: mandates::recipient_swap,
    },
    Attack {
        id: "attachment_swap",
        title: "attachment added after approval",
        run: mandates::attachment_swap,
    },
    Attack {
        id: "cross_tenant_mandate",
        title: "another tenant's approver signs for this tenant",
        run: mandates::cross_tenant,
    },
    Attack {
        id: "level_downgrade",
        title: "A1 button approval for a draft that needs A2",
        run: mandates::level_downgrade,
    },
    Attack {
        id: "unknown_channel",
        title: "proof from a channel the gate does not know",
        run: mandates::unknown_channel,
    },
    Attack {
        id: "open_mandate_by_policy",
        title: "open mandate signed without a human channel",
        run: mandates::open_by_policy,
    },
    Attack {
        id: "open_mandate_slot_smuggle",
        title: "link smuggled through an open-mandate template slot",
        run: mandates::open_slot_smuggle,
    },
    Attack {
        id: "open_mandate_rate",
        title: "hijacked agent floods under an open mandate",
        run: mandates::open_rate,
    },
    Attack {
        id: "second_open_mandate",
        title: "new open mandate presented before the previous is refused",
        run: mandates::second_open,
    },
    Attack {
        id: "canary_block",
        title: "canary marker released with a valid approval",
        run: gate::canary_block,
    },
    Attack {
        id: "canary_obfuscated",
        title: "canary hidden by case, separators or base64",
        run: gate::canary_obfuscated,
    },
    Attack {
        id: "agent_approve_absent",
        title: "agent calls approve or an alias",
        run: gate::agent_approve_absent,
    },
    Attack {
        id: "revise_after_approval",
        title: "draft edited after the owner approved it",
        run: gate::revise_after_approval,
    },
    Attack {
        id: "classifier_says_safe",
        title: "fuzzy safe verdict lowers free text below A1",
        run: gate::classifier_says_safe,
    },
    Attack {
        id: "share_outside_shelf",
        title: "share pointer to a document not open to the peer",
        run: gate::share_outside_shelf,
    },
    Attack {
        id: "share_path_traversal",
        title: "share pointer escaping the shelf with ..",
        run: gate::share_path_traversal,
    },
    Attack {
        id: "share_note_smuggle",
        title: "share note carrying a link or a number",
        run: gate::share_note_smuggle,
    },
    Attack {
        id: "envelope_forged",
        title: "gate envelope signed by an unpaired key",
        run: gate::envelope_forged,
    },
    Attack {
        id: "envelope_replay",
        title: "gate envelope delivered twice",
        run: gate::envelope_replay,
    },
    Attack {
        id: "cross_tenant_nonce",
        title: "nonce issued for one tenant consumed by another",
        run: gate::cross_tenant_nonce,
    },
    Attack {
        id: "button_pressed_by_stranger",
        title: "A1 button pressed by a Telegram user who is not the owner",
        run: pending_bot,
    },
    Attack {
        id: "mini_app_hmac_only",
        title: "Mini App initData valid by bot-token HMAC only",
        run: pending_bot,
    },
    Attack {
        id: "mini_app_stale_auth_date",
        title: "Mini App initData with an old auth_date",
        run: pending_bot,
    },
    Attack {
        id: "approval_text_in_chat",
        title: "peer or agent text that looks like an owner approval",
        run: pending_bot,
    },
    Attack {
        id: "config_edit_without_consent",
        title: "security settings changed by editing config",
        run: pending_server,
    },
    Attack {
        id: "cross_tenant_http",
        title: "tenant A's agent token reads tenant B's drafts",
        run: pending_server,
    },
    Attack {
        id: "agent_reaches_approval_endpoint",
        title: "agent-facing listener serves an approval route",
        run: pending_server,
    },
];

/// Runs every attack.
pub fn run_all() -> Vec<(&'static Attack, Outcome)> {
    ATTACKS.iter().map(|a| (a, (a.run)())).collect()
}

/// Runs the attack with `id`; `None` if there is no such attack.
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
