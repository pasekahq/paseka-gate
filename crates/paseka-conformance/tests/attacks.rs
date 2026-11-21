//! One test per conformance attack CA-n. Pending attacks are ignored with the missing part.

use paseka_conformance::{ATTACKS, Outcome, run};

fn check(id: &str) {
    match run(id) {
        Some(Outcome::Pass) => {}
        other => panic!("{id}: {other:?}"),
    }
}

#[test]
fn attacks_are_numbered_ca_1_to_54_in_order() {
    assert_eq!(ATTACKS.len(), 54);
    for (i, a) in ATTACKS.iter().enumerate() {
        assert_eq!(a.id, format!("CA-{}", i + 1));
    }
}

#[test]
fn ca01_no_approve_tool() {
    check("CA-1");
}

#[test]
fn ca02_proof_like_fields() {
    check("CA-2");
}

#[test]
fn ca03_unanswered_prompt_expires() {
    check("CA-3");
}

#[test]
#[ignore = "needs the consent bot and Mini App"]
fn ca04_forged_telegram_update_without_wrong() {
    check("CA-4");
}

#[test]
#[ignore = "needs the gate daemon"]
fn ca05_evidenceshaped_json_journal_inbox_draft() {
    check("CA-5");
}

#[test]
fn ca06_old_button_after_revise() {
    check("CA-6");
}

#[test]
fn ca07_revise_or_withdraw_after_approval() {
    check("CA-7");
}

#[test]
fn ca08_attachment_swap() {
    check("CA-8");
}

#[test]
fn ca09_miniapp_digest_mismatch() {
    check("CA-9");
}

#[test]
fn ca10_double_press() {
    check("CA-10");
}

#[test]
#[ignore = "needs the consent bot and Mini App"]
fn ca11_mini_app_decision_replayed_same() {
    check("CA-11");
}

#[test]
fn ca12_envelope_replay() {
    check("CA-12");
}

#[test]
fn ca13_press_after_ttl() {
    check("CA-13");
}

#[test]
#[ignore = "needs the consent bot and Mini App"]
fn ca14_initdata_stale_future_authdate() {
    check("CA-14");
}

#[test]
fn ca15_non_approver() {
    check("CA-15");
}

#[test]
#[ignore = "needs the consent bot and Mini App"]
fn ca16_initdata_valid_bottoken_hmac_only() {
    check("CA-16");
}

#[test]
#[ignore = "needs the consent bot and Mini App"]
fn ca17_initdata_signed_for_another_bot() {
    check("CA-17");
}

#[test]
fn ca18_classifier_says_safe() {
    check("CA-18");
}

#[test]
fn ca19_canary_blocks() {
    check("CA-19");
}

#[test]
fn ca20_owner_edit_with_canary() {
    check("CA-20");
}

#[test]
fn ca21_level_without_channel() {
    check("CA-21");
}

#[test]
fn ca22_no_oracle() {
    check("CA-22");
}

#[test]
#[ignore = "needs the gate daemon"]
fn ca23_security_settings_edited_config_after() {
    check("CA-23");
}

#[test]
fn ca24_no_settings_side_path() {
    check("CA-24");
}

#[test]
fn ca25_open_mandate_bounds() {
    check("CA-25");
}

#[test]
fn ca26_template_field_smuggle() {
    check("CA-26");
}

#[test]
fn ca27_revoked_mandate() {
    check("CA-27");
}

#[test]
fn ca28_second_open_mandate() {
    check("CA-28");
}

#[test]
fn ca29_share_outside_shelf() {
    check("CA-29");
}

#[test]
fn ca30_share_note_smuggle() {
    check("CA-30");
}

#[test]
fn ca31_forged_envelopes() {
    check("CA-31");
}

#[test]
fn ca32_cross_tenant_envelope() {
    check("CA-32");
}

#[test]
fn ca33_wire_windows() {
    check("CA-33");
}

#[test]
fn ca34_mandate_mismatch() {
    check("CA-34");
}

#[test]
#[ignore = "needs invite codes"]
fn ca35_used_expired_invite_code() {
    check("CA-35");
}

#[test]
fn ca36_pairing_pending() {
    check("CA-36");
}

#[test]
fn ca37_pair_accept_signed_key_other() {
    check("CA-37");
}

#[test]
#[ignore = "needs the gate daemon"]
fn ca38_tenant_as_agent_token_tenant() {
    check("CA-38");
}

#[test]
fn ca39_cross_tenant_decision() {
    check("CA-39");
}

#[test]
fn ca40_invisible_characters() {
    check("CA-40");
}

#[test]
fn ca41_over_prompt_capacity() {
    check("CA-41");
}

#[test]
#[ignore = "needs an installed gate"]
fn ca42_agents_unix_user_reads_gate() {
    check("CA-42");
}

#[test]
#[ignore = "needs the gate daemon"]
fn ca43_agent_proposes_100_drafts_minute() {
    check("CA-43");
}

#[test]
#[ignore = "needs the gate daemon"]
fn ca44_peer_burst_above_its_volume() {
    check("CA-44");
}

#[test]
#[ignore = "needs the journal"]
fn ca45_one_journal_row_modified_database() {
    check("CA-45");
}

#[test]
#[ignore = "needs the gate daemon"]
fn ca46_gate_killed_between_decision_and() {
    check("CA-46");
}

#[test]
fn ca47_weaker_channel() {
    check("CA-47");
}

#[test]
fn ca48_key_substitution() {
    check("CA-48");
}

#[test]
fn ca49_rotation_not_by_current_key() {
    check("CA-49");
}

#[test]
fn ca50_previous_key_after_grace() {
    check("CA-50");
}

#[test]
fn ca51_thief_moves_peer_to_own_key() {
    check("CA-51");
}

#[test]
fn ca52_revoked_key_used() {
    check("CA-52");
}

#[test]
fn ca53_clear_tripwire_without_pin() {
    check("CA-53");
}

#[test]
fn ca54_never_source_leaves() {
    check("CA-54");
}
