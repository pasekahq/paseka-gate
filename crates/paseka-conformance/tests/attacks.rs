//! One test per conformance attack. Pending attacks are ignored until the gate server exists.

use paseka_conformance::{Outcome, run};

fn check(id: &str) {
    match run(id) {
        Some(Outcome::Pass) => {}
        other => panic!("{id}: {other:?}"),
    }
}

#[test]
fn forged_mandate() {
    check("forged_mandate");
}

#[test]
fn tampered_mandate() {
    check("tampered_mandate");
}

#[test]
fn alg_confusion() {
    check("alg_confusion");
}

#[test]
fn expired_mandate() {
    check("expired_mandate");
}

#[test]
fn overlong_mandate() {
    check("overlong_mandate");
}

#[test]
fn replayed_mandate() {
    check("replayed_mandate");
}

#[test]
fn stale_nonce() {
    check("stale_nonce");
}

#[test]
fn preview_swap() {
    check("preview_swap");
}

#[test]
fn recipient_swap() {
    check("recipient_swap");
}

#[test]
fn attachment_swap() {
    check("attachment_swap");
}

#[test]
fn cross_tenant_mandate() {
    check("cross_tenant_mandate");
}

#[test]
fn level_downgrade() {
    check("level_downgrade");
}

#[test]
fn unknown_channel() {
    check("unknown_channel");
}

#[test]
fn open_mandate_by_policy() {
    check("open_mandate_by_policy");
}

#[test]
fn open_mandate_slot_smuggle() {
    check("open_mandate_slot_smuggle");
}

#[test]
fn open_mandate_rate() {
    check("open_mandate_rate");
}

#[test]
fn second_open_mandate() {
    check("second_open_mandate");
}

#[test]
fn canary_block() {
    check("canary_block");
}

#[test]
fn canary_obfuscated() {
    check("canary_obfuscated");
}

#[test]
fn agent_approve_absent() {
    check("agent_approve_absent");
}

#[test]
fn revise_after_approval() {
    check("revise_after_approval");
}

#[test]
fn classifier_says_safe() {
    check("classifier_says_safe");
}

#[test]
fn share_outside_shelf() {
    check("share_outside_shelf");
}

#[test]
fn share_path_traversal() {
    check("share_path_traversal");
}

#[test]
fn share_note_smuggle() {
    check("share_note_smuggle");
}

#[test]
fn envelope_forged() {
    check("envelope_forged");
}

#[test]
fn envelope_replay() {
    check("envelope_replay");
}

#[test]
fn cross_tenant_nonce() {
    check("cross_tenant_nonce");
}

#[test]
#[ignore = "needs a running gate"]
fn button_pressed_by_stranger() {
    check("button_pressed_by_stranger");
}

#[test]
#[ignore = "needs a running gate"]
fn mini_app_hmac_only() {
    check("mini_app_hmac_only");
}

#[test]
#[ignore = "needs a running gate"]
fn mini_app_stale_auth_date() {
    check("mini_app_stale_auth_date");
}

#[test]
#[ignore = "needs a running gate"]
fn approval_text_in_chat() {
    check("approval_text_in_chat");
}

#[test]
#[ignore = "needs a running gate"]
fn config_edit_without_consent() {
    check("config_edit_without_consent");
}

#[test]
#[ignore = "needs a running gate"]
fn cross_tenant_http() {
    check("cross_tenant_http");
}

#[test]
#[ignore = "needs a running gate"]
fn agent_reaches_approval_endpoint() {
    check("agent_reaches_approval_endpoint");
}
