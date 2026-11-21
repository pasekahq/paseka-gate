use super::*;
use crate::testkit::free;

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
fn near_verbatim_quote_of_a_sensitive_document_needs_a2_plus() {
    let mut r = OwnerRules::default();
    r.add_fingerprint(
        "The quarterly review found that the merger talks with the northern partner stalled \
         because the valuation gap stayed too wide for both boards to accept.",
    );
    let quote = "Between us: the merger talks with the Northern partner stalled, because the valuation gap stayed too wide.";
    let a = assess(&r, &free(quote));
    assert_eq!(a.required, Required::Level(Level::A2Plus));
    let unrelated = "The weather was nice and we walked along the river for an hour before lunch.";
    assert_eq!(
        assess(&r, &free(unrelated)).required,
        Required::Level(Level::A1)
    );
}

#[test]
fn sensitive_source_read_needs_a2_plus() {
    let r = OwnerRules::default();
    let src = [SourceRead {
        sensitive: true,
        verified: true,
    }];
    let d = Draft {
        sources: &src,
        ..free("ok")
    };
    assert_eq!(assess(&r, &d).required, Required::Level(Level::A2Plus));
}
