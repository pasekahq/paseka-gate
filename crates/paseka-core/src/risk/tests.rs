use super::*;
use crate::source::{Access, BuiltIn, Source, SourceId, SourceKind, SourceRegistry};
use crate::testkit::{
    BOB_INBOUND, CARD, CHAT, DOCUMENT, FILES, MAIL, QUOTE, SECRET, address, audiences, free,
    settle, tenant,
};

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
fn a_canary_in_attachment_text_blocks_like_one_in_the_body() {
    let mut r = OwnerRules::default();
    r.add_canary(CanaryId(7), "PASEKA-CANARY-7f3a9c").unwrap();
    for attachment_text in [
        &["notes", "fyi PASEKA-CANARY-7f3a9c"][..],
        &["blob UEFTRUtBLUNBTkFSWS03ZjNhOWM"][..],
    ] {
        let a = assess(
            &r,
            &Draft {
                attachment_text,
                ..free("see the attached file")
            },
        );
        assert_eq!(a.required, Required::Block, "{attachment_text:?}");
        assert_eq!(a.canaries, vec![CanaryId(7)], "{attachment_text:?}");
    }
    let clean = Draft {
        attachment_text: &["nothing here"],
        ..free("see the attached file")
    };
    assert_eq!(assess(&r, &clean).canaries, vec![]);
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

fn one_time_codes_in(text: &str) -> Vec<&str> {
    structural(text)
        .into_iter()
        .filter(|f| f.kind == FlagKind::OneTimeCode)
        .map(|f| &text[f.start.unwrap()..f.end.unwrap()])
        .collect()
}

#[test]
fn a_code_next_to_a_code_keyword_is_a_one_time_code() {
    let cases: [(&str, &str); 12] = [
        ("Your verification code is 482913.", "482913"),
        ("482913 is your login code", "482913"),
        ("OTP: 4821", "4821"),
        ("2FA code 123 456, do not share it", "123 456"),
        ("use code 123-456 to sign in", "123-456"),
        ("one-time passcode 70114825", "70114825"),
        ("MFA (4829)", "4829"),
        ("Ваш код: 5821", "5821"),
        ("Код подтверждения 482913", "482913"),
        ("482913, одноразовый пароль", "482913"),
        ("код верификации: 3017", "3017"),
        (
            "otpauth://totp/example.org:alice?secret=AAAAAAAA&issuer=example.org",
            "otpauth://totp/example.org:alice?secret=AAAAAAAA&issuer=example.org",
        ),
    ];
    for (text, code) in cases {
        assert_eq!(one_time_codes_in(text), vec![code], "{text:?}");
    }
}

#[test]
fn numbers_without_a_code_keyword_nearby_are_no_one_time_code() {
    for text in [
        "I have 4821 apples",
        "the meeting moved to 2026-11-30 at 18:00",
        "it costs 1999 EUR, or $4821 with tax",
        "call +1 555 010 9999",
        "call 555 0100 tomorrow",
        "the code freeze starts in 2027",
        "zip code 94105",
        "error code 5003 again",
        "код ошибки 5003",
        "a verification step is needed; the office is room 4821 on the far side",
        "code 30.11.2026",
        "code 12",
        "code 123456789",
    ] {
        assert_eq!(one_time_codes_in(text), Vec::<&str>::new(), "{text:?}");
    }
}

#[test]
fn a_year_like_code_directly_after_a_code_keyword_is_a_one_time_code() {
    for (text, code) in [
        ("your code is 2048", "2048"),
        ("code: 1984", "1984"),
        ("код: 1984", "1984"),
        ("Ваш код \u{2014} 2010", "2010"),
        ("OTP 2024", "2024"),
        ("2FA: 1999, do not share it", "1999"),
        ("verification code = 2099.", "2099"),
    ] {
        assert_eq!(one_time_codes_in(text), vec![code], "{text:?}");
    }
}

#[test]
fn a_year_apart_from_a_code_keyword_is_no_one_time_code() {
    for text in [
        "we met in 1999",
        "a customer since 2024",
        "the code review in 2023 went well",
        "code is from 1999",
        "zip code 1999",
        "error code: 2001",
        "код ошибки: 2001",
    ] {
        assert_eq!(one_time_codes_in(text), Vec::<&str>::new(), "{text:?}");
    }
}

#[test]
fn a_one_time_code_blocks_under_any_decision_approval_or_open_mandate() {
    let mut reg = SourceRegistry::default();
    reg.register(&tenant(1), FILES, SourceKind::Files).unwrap();
    settle(
        &mut reg,
        Source::BuiltIn(BuiltIn::Secrets),
        &address(2),
        Access::Allow,
    );
    let decisions = reg.towards(&tenant(1), &address(2));
    for open_mandate in [false, true] {
        let d = Draft {
            decisions: &decisions,
            open_mandate,
            ..free("your code is 482913")
        };
        let a = assess(&OwnerRules::default(), &d);
        assert_eq!(a.required, Required::Block);
        assert_eq!(
            a.flags[0].source,
            Some(Source::BuiltIn(BuiltIn::OneTimeCodes))
        );
    }
}

const VAULT: SourceId = SourceId(5);
const VAULT_VALUE: &str = "alice-vault-aaaaaaaa";

fn vault_rules() -> OwnerRules {
    let mut r = OwnerRules::default();
    r.add_vault_secret(VAULT, VAULT_VALUE).unwrap();
    r
}

#[test]
fn a_vault_secret_in_the_body_or_an_attachment_reports_its_source_without_its_value() {
    let r = vault_rules();
    let body = format!("the password is {VAULT_VALUE} ok");
    for (text, attachment_text) in [
        (body.as_str(), &[][..]),
        ("see the attached file", &[VAULT_VALUE][..]),
    ] {
        let a = assess(
            &r,
            &Draft {
                attachment_text,
                ..free(text)
            },
        );
        assert_eq!(a.required, Required::Level(Level::A2), "{text}");
        let hits: Vec<&Flag> = a
            .flags
            .iter()
            .filter(|f| f.kind == FlagKind::VaultSecret)
            .collect();
        assert_eq!(hits.len(), 1, "{text}");
        assert_eq!(hits[0].source, Some(Source::Registered(VAULT)));
        assert!(!format!("{a:?}").contains(VAULT_VALUE), "{a:?}");
    }
    let assessed = assess(&r, &free(&body));
    let hit = assessed
        .flags
        .iter()
        .find(|f| f.kind == FlagKind::VaultSecret)
        .unwrap();
    assert_eq!(&body[hit.start.unwrap()..hit.end.unwrap()], VAULT_VALUE);
    assert!(!format!("{r:?}").contains(VAULT_VALUE));
}

#[test]
fn a_vault_secret_matches_its_exact_value_only_and_has_a_minimum_length() {
    let r = vault_rules();
    for text in [
        "alice-vault-aaaaaaa",
        "ALICE-VAULT-AAAAAAAA",
        "alice vault aaaaaaaa",
    ] {
        let a = assess(&r, &free(text));
        assert!(
            a.flags.iter().all(|f| f.kind != FlagKind::VaultSecret),
            "{text}"
        );
    }
    let mut r = OwnerRules::default();
    assert_eq!(
        r.add_vault_secret(VAULT, "aaaaaaa"),
        Err(VaultSecretTooShort)
    );
    assert_eq!(r.add_vault_secret(VAULT, "аааааааа"), Ok(()));
}

#[test]
fn the_registry_decides_a_vault_secret_per_peer() {
    let mut reg = SourceRegistry::default();
    reg.register(&tenant(1), VAULT, SourceKind::VaultSecret)
        .unwrap();
    settle(
        &mut reg,
        Source::Registered(VAULT),
        &address(2),
        Access::Never,
    );
    settle(
        &mut reg,
        Source::Registered(VAULT),
        &address(3),
        Access::Allow,
    );
    let text = format!("use {VAULT_VALUE}");
    let cases = [
        (2, Required::Block),
        (3, Required::Level(Level::A0)),
        (4, Required::Level(Level::A2)),
    ];
    for (peer, want) in cases {
        let decisions = reg.towards(&tenant(1), &address(peer));
        let d = Draft {
            decisions: &decisions,
            open_mandate: true,
            ..free(&text)
        };
        assert_eq!(assess(&vault_rules(), &d).required, want, "peer {peer}");
    }
}

fn private_links_in(rules: &OwnerRules, text: &str) -> Vec<String> {
    let mut a = assess(rules, &free(text));
    a.flags.append(&mut a.allowed);
    a.flags
        .into_iter()
        .filter(|f| f.kind == FlagKind::PrivateLink)
        .map(|f| {
            assert_eq!(f.source, Some(Source::BuiltIn(BuiltIn::PrivateLinks)));
            f.detail
        })
        .collect()
}

#[test]
fn links_on_a_private_link_domain_or_with_an_access_token_are_private_links() {
    let r = OwnerRules::default();
    let cases: [(&str, &str); 12] = [
        (
            "https://docs.google.com/document/d/AAAA/edit",
            "docs.google.com",
        ),
        ("drive.google.com/file/d/AAAA/view", "drive.google.com"),
        ("https://www.dropbox.com/s/aaaa/plan.pdf", "dropbox.com"),
        ("https://alice.sharepoint.com/:w:/g/AAAA", "sharepoint.com"),
        ("https://t.me/+AAAAAAAA", "t.me/+"),
        ("https://t.me/joinchat/AAAAAAAA", "t.me/joinchat"),
        ("https://discord.gg/aaaa", "discord.gg"),
        (
            "https://example.org/f.pdf?X-Amz-Signature=AAAA",
            "x-amz-signature in the query",
        ),
        ("https://example.org/f.pdf?a=1&sig=AAAA", "sig in the query"),
        ("https://example.org/login?token=AAAA", "token in the query"),
        (
            "https://example.org/cb#access_token=AAAA",
            "access_token in the query",
        ),
        ("https://example.org/m?magic=AAAA", "magic in the query"),
    ];
    for (text, detail) in cases {
        assert_eq!(private_links_in(&r, text), vec![detail], "{text}");
    }
}

#[test]
fn ordinary_links_are_no_private_links() {
    let r = OwnerRules::default();
    for text in [
        "https://example.org/a?id=7&page=2",
        "https://example.org/a?token=",
        "https://t.me/example_channel",
        "https://notdropbox.com/s/aaaa",
        "https://example.org/docs.google.com",
        "mailto:alice@example.org",
    ] {
        assert_eq!(private_links_in(&r, text), Vec::<String>::new(), "{text}");
    }
}

#[test]
fn an_owner_entry_adds_a_private_link_domain_and_the_registry_decides_per_peer() {
    let mut r = OwnerRules::default();
    r.add_private_link_domain("Files.Example.org/share");
    let link = "https://cdn.files.example.org/share/AAAA";
    assert_eq!(private_links_in(&r, link), vec!["files.example.org/share"]);
    assert_eq!(
        private_links_in(&r, "https://files.example.org/public/a"),
        Vec::<String>::new()
    );
    let mut reg = SourceRegistry::default();
    let links = Source::BuiltIn(BuiltIn::PrivateLinks);
    settle(&mut reg, links, &address(2), Access::Never);
    settle(&mut reg, links, &address(3), Access::Allow);
    for (peer, want) in [
        (2, Required::Block),
        (3, Required::Level(Level::A2)),
        (4, Required::Level(Level::A2)),
    ] {
        let decisions = reg.towards(&tenant(1), &address(peer));
        let d = Draft {
            decisions: &decisions,
            ..free(link)
        };
        let a = assess(&r, &d);
        assert_eq!(a.required, want, "peer {peer}");
        let flagged = a.flags.iter().any(|f| f.kind == FlagKind::PrivateLink);
        assert_eq!(flagged, peer != 3, "peer {peer}");
    }
}

#[test]
fn a_quote_of_a_chat_needs_consent_only_outside_the_chat_and_a_peers_own_words_go_back() {
    let reg = audiences();
    let mut chat = OwnerRules::default();
    chat.add_fingerprint(CHAT, DOCUMENT);
    let mut inbound = OwnerRules::default();
    inbound.add_fingerprint(BOB_INBOUND, DOCUMENT);
    let a0 = Required::Level(Level::A0);
    let a2p = Required::Level(Level::A2Plus);
    for (rules, peer, want) in [
        (&chat, 2, a0),
        (&chat, 3, a0),
        (&chat, 4, a2p),
        (&inbound, 2, a0),
        (&inbound, 3, a2p),
    ] {
        let decisions = reg.towards(&tenant(1), &address(peer));
        let d = Draft {
            decisions: &decisions,
            open_mandate: true,
            ..free(QUOTE)
        };
        assert_eq!(assess(rules, &d).required, want, "peer {peer}");
    }
}
