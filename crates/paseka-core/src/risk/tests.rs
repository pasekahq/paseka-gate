use super::*;
use crate::source::{Access, BuiltIn, Source, SourceKind, SourceRegistry};
use crate::testkit::{CARD, DOCUMENT, FILES, MAIL, QUOTE, SECRET, address, free, settle, tenant};

fn kinds(text: &str) -> Vec<FlagKind> {
    let mut k: Vec<FlagKind> = structural(text).into_iter().map(|f| f.kind).collect();
    k.sort();
    k.dedup();
    k
}

#[test]
fn plain_prose_has_no_structural_flags() {
    assert_eq!(
        kinds("I think the plan for 2026-11-18 is fine, see you at 18:00."),
        vec![]
    );
}

#[test]
fn structural_detectors_find_each_kind() {
    let cases: [(&str, FlagKind); 13] = [
        ("go to https://example.org/a", FlagKind::Link),
        ("go to example.org/a", FlagKind::Link),
        ("www.example.org", FlagKind::Link),
        ("data:text/html,hi", FlagKind::Link),
        (
            "blob aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgc2VjcmV0IGJsb2I=",
            FlagKind::Base64Blob,
        ),
        ("0123456789abcdef0123456789abcdef", FlagKind::HexBlob),
        ("call +1 555 010 9999", FlagKind::LongNumber),
        ("card 4111 1111 1111 1111", FlagKind::CardNumber),
        ("iban GB82 WEST 1234 5698 7654 32 thanks", FlagKind::Iban),
        ("key sk-abcdefghijklmnopqrstuvwxyz", FlagKind::Secret),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\nabc", FlagKind::Secret),
        ("hi\u{200b}there", FlagKind::InvisibleChar),
        ("bell\u{7}here", FlagKind::InvisibleChar),
    ];
    for (text, kind) in cases {
        assert!(kinds(text).contains(&kind), "{text:?} -> {:?}", kinds(text));
    }
}

#[test]
fn tag_characters_used_for_ascii_smuggling_are_flagged() {
    assert!(kinds("ok\u{e0041}\u{e0042}").contains(&FlagKind::InvisibleChar));
}

#[test]
fn checksum_detectors_ignore_invalid_numbers() {
    assert!(!kinds("4111 1111 1111 1112").contains(&FlagKind::CardNumber));
    assert!(!kinds("GB82 WEST 1234 5698 7654 33").contains(&FlagKind::Iban));
}

#[test]
fn flags_carry_the_matched_byte_range() {
    let text = "see https://example.org/x now";
    let f = structural(text)
        .into_iter()
        .find(|f| f.kind == FlagKind::Link)
        .unwrap();
    assert_eq!(
        &text[f.start.unwrap()..f.end.unwrap()],
        "https://example.org/x"
    );
}

#[test]
fn free_text_needs_a1_templates_a0_only_under_a_mandate_and_any_flag_a2() {
    let r = OwnerRules::default();
    assert_eq!(
        assess(&r, &free("sounds good")).required,
        Required::Level(Level::A1)
    );
    let s = Draft {
        kind: OutputKind::Template,
        ..free("yes")
    };
    assert_eq!(assess(&r, &s).required, Required::Level(Level::A1));
    let s = Draft {
        open_mandate: true,
        ..s
    };
    assert_eq!(assess(&r, &s).required, Required::Level(Level::A0));
    let s = Draft {
        kind: OutputKind::Template,
        ..free("yes, https://example.org/x")
    };
    assert_eq!(assess(&r, &s).required, Required::Level(Level::A2));
    let att = Draft {
        attachments: 1,
        ..free("see attached")
    };
    assert_eq!(assess(&r, &att).required, Required::Level(Level::A2));
    let new = Draft {
        new_recipient: true,
        ..free("hello")
    };
    assert_eq!(assess(&r, &new).required, Required::Level(Level::A2));
    let long = "a ".repeat(DEFAULT_MAX_LEN);
    assert_eq!(
        assess(&r, &free(&long)).required,
        Required::Level(Level::A2)
    );
}

#[test]
fn a_fuzzy_safe_verdict_never_lowers_the_level() {
    let r = OwnerRules::default();
    let d = Draft {
        fuzzy_hint: Some(Level::A0),
        ..free("sounds good")
    };
    assert_eq!(assess(&r, &d).required, Required::Level(Level::A1));
    let d = Draft {
        fuzzy_hint: Some(Level::A3),
        ..free("sounds good")
    };
    assert_eq!(assess(&r, &d).required, Required::Level(Level::A2));
}

#[test]
fn open_mandate_releases_at_a0_only_without_any_flag() {
    let r = OwnerRules::default();
    let clean = Draft {
        open_mandate: true,
        ..free("sounds good")
    };
    assert_eq!(assess(&r, &clean).required, Required::Level(Level::A0));
    let link = Draft {
        open_mandate: true,
        ..free("see https://example.org/x")
    };
    assert_eq!(assess(&r, &link).required, Required::Level(Level::A2));
    let tripwire = Draft {
        open_mandate: true,
        tripwire: true,
        ..free("sounds good")
    };
    assert_eq!(
        assess(&r, &tripwire).required,
        Required::Level(Level::A2Plus)
    );
}

#[test]
fn dictionary_hit_is_case_insensitive_and_highlighted() {
    let mut r = OwnerRules::default();
    r.add_term("Diagnosis");
    let text = "My DIAGNOSIS is private";
    let a = assess(&r, &free(text));
    assert_eq!(a.required, Required::Level(Level::A2));
    let f = a
        .flags
        .iter()
        .find(|f| f.kind == FlagKind::Dictionary)
        .unwrap();
    assert_eq!(&text[f.start.unwrap()..f.end.unwrap()], "DIAGNOSIS");
}

#[test]
fn canary_blocks_even_when_obfuscated() {
    let mut r = OwnerRules::default();
    r.add_canary(CanaryId(7), "PASEKA-CANARY-7f3a9c").unwrap();
    for text in [
        "fyi PASEKA-CANARY-7f3a9c",
        "fyi paseka canary 7f3a9c",
        "p.a.s.e.k.a-c\u{200b}anary-7F3A9C",
        "blob UEFTRUtBLUNBTkFSWS03ZjNhOWM",
        "hex 504153454b412d43414e4152592d376633613963",
    ] {
        let a = assess(&r, &free(text));
        assert_eq!(a.required, Required::Block, "{text}");
        assert_eq!(a.canaries, vec![CanaryId(7)], "{text}");
    }
    let clean = assess(&r, &free("nothing here"));
    assert_eq!(clean.required, Required::Level(Level::A1));
    assert_eq!(clean.canaries, vec![]);
    assert_eq!(r.add_canary(CanaryId(8), "ab-1"), Err(CanaryTooShort));
}

#[test]
fn every_matching_canary_is_named_by_id_and_no_flag_carries_its_marker() {
    let mut r = OwnerRules::default();
    r.add_canary(CanaryId(1), "PASEKA-CANARY-7f3a9c").unwrap();
    r.add_canary(CanaryId(2), "PASEKA-CANARY-unused").unwrap();
    r.add_canary(CanaryId(3), "PASEKA-CANARY-b81d04").unwrap();
    let a = assess(
        &r,
        &free("fyi PASEKA-CANARY-b81d04 and PASEKA-CANARY-7f3a9c"),
    );
    assert_eq!(a.canaries, vec![CanaryId(1), CanaryId(3)]);
    assert!(
        a.flags
            .iter()
            .all(|f| !f.detail.contains("7f3a9c") && !f.detail.contains("b81d04")),
        "{:?}",
        a.flags
    );
}

#[test]
fn near_verbatim_quote_of_a_registered_document_needs_a2_plus_under_ask() {
    let mut r = OwnerRules::default();
    r.add_fingerprint(FILES, DOCUMENT);
    let a = assess(&r, &free(QUOTE));
    assert_eq!(a.required, Required::Level(Level::A2Plus));
    assert_eq!(a.flags[0].source, Some(Source::Registered(FILES)));
    let unrelated = "The weather was nice and we walked along the river for an hour before lunch.";
    assert_eq!(
        assess(&r, &free(unrelated)).required,
        Required::Level(Level::A1)
    );
}

/// Tenant 1 with files source 1 and mail source 2; towards bob (address 2) secrets Allow, files
/// Never, mail Allow; towards carol (address 3) secrets Never, files Allow, personal ids Allow.
fn registry() -> SourceRegistry {
    let mut reg = SourceRegistry::default();
    reg.register(&tenant(1), FILES, SourceKind::Files).unwrap();
    reg.register(&tenant(1), MAIL, SourceKind::Mcp).unwrap();
    let (bob, carol) = (address(2), address(3));
    let secrets = Source::BuiltIn(BuiltIn::Secrets);
    settle(&mut reg, secrets, &bob, Access::Allow);
    settle(&mut reg, Source::Registered(FILES), &bob, Access::Never);
    settle(&mut reg, Source::Registered(MAIL), &bob, Access::Allow);
    settle(&mut reg, secrets, &carol, Access::Never);
    settle(&mut reg, Source::Registered(FILES), &carol, Access::Allow);
    settle(
        &mut reg,
        Source::BuiltIn(BuiltIn::PersonalIds),
        &carol,
        Access::Allow,
    );
    reg
}

#[test]
fn the_registry_decision_towards_the_recipient_sets_each_source_stage_floor() {
    let reg = registry();
    let mut rules = OwnerRules::default();
    rules.add_fingerprint(FILES, DOCUMENT);
    let read = |source| {
        [SourceRead {
            source,
            verified: true,
        }]
    };
    let mail = read(MAIL);
    let files = read(FILES);
    let none: [SourceRead; 0] = [];
    let a1 = Required::Level(Level::A1);
    let a2 = Required::Level(Level::A2);
    let a2p = Required::Level(Level::A2Plus);
    let a0 = Required::Level(Level::A0);
    let cases: [(u8, &str, &[SourceRead], bool, Required); 22] = [
        (2, SECRET, &none, false, a1),
        (2, SECRET, &none, true, a0),
        (3, SECRET, &none, false, Required::Block),
        (3, SECRET, &none, true, Required::Block),
        (4, SECRET, &none, false, a2),
        (4, SECRET, &none, true, a2),
        (2, CARD, &none, false, a2),
        (3, CARD, &none, false, a1),
        (3, CARD, &none, true, a0),
        (2, QUOTE, &none, false, Required::Block),
        (2, QUOTE, &none, true, Required::Block),
        (3, QUOTE, &none, false, a1),
        (3, QUOTE, &none, true, a0),
        (4, QUOTE, &none, false, a2p),
        (4, QUOTE, &none, true, a2p),
        (2, "ok", &mail, false, a1),
        (2, "ok", &mail, true, a0),
        (3, "ok", &mail, false, a2p),
        (3, "ok", &mail, true, a2p),
        (2, "ok", &files, false, Required::Block),
        (3, "ok", &files, true, a0),
        (
            2,
            "key sk-abcdefghijklmnopqrstuvwxyz at https://example.org/x",
            &none,
            true,
            a2,
        ),
    ];
    for (peer, text, sources, open_mandate, want) in cases {
        let decisions = reg.towards(&tenant(1), &address(peer));
        let d = Draft {
            sources,
            decisions: &decisions,
            open_mandate,
            ..free(text)
        };
        assert_eq!(
            assess(&rules, &d).required,
            want,
            "peer {peer}, {text:?}, {sources:?}, open mandate {open_mandate}"
        );
    }
}

#[test]
fn an_allowed_hit_is_shown_to_the_owner_with_its_source_but_is_no_flag() {
    let reg = registry();
    let decisions = reg.towards(&tenant(1), &address(2));
    let d = Draft {
        decisions: &decisions,
        ..free(SECRET)
    };
    let a = assess(&OwnerRules::default(), &d);
    assert_eq!(a.flags, vec![]);
    assert_eq!(a.allowed.len(), 1);
    assert_eq!(a.allowed[0].kind, FlagKind::Secret);
    assert_eq!(a.allowed[0].source, Some(Source::BuiltIn(BuiltIn::Secrets)));
}

#[test]
fn an_allow_for_one_peer_reaches_neither_another_peer_nor_another_tenant() {
    let reg = registry();
    let assess_to = |t: u8, peer: u8| {
        let decisions = reg.towards(&tenant(t), &address(peer));
        let d = Draft {
            decisions: &decisions,
            ..free(SECRET)
        };
        assess(&OwnerRules::default(), &d).required
    };
    assert_eq!(assess_to(1, 2), Required::Level(Level::A1));
    assert_eq!(assess_to(1, 4), Required::Level(Level::A2));
    assert_eq!(assess_to(2, 2), Required::Level(Level::A2));
}
