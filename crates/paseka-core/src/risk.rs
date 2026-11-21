//! Risk evaluation: which approval level a draft needs, or whether it is blocked.
//!
//! Every check can only raise the requirement ([`Assessment::raise`]); none can lower it. Free
//! text needs at least A1 whatever a classifier says. Exact detectors (structure, dictionary,
//! canaries, fingerprints) run here; fuzzy signals arrive as an optional level hint. Stages S4,
//! S5, S8 and S9 report the source they matched, and the source registry's decision towards the
//! recipient sets their floor.

mod sources;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use paseka_proto::Level;

use crate::source::{Access, BuiltIn, Decisions, Source, SourceId};

pub use sources::{DEFAULT_PRIVATE_LINK_DOMAINS, MIN_VAULT_SECRET_CHARS, VaultSecretTooShort};

/// Default maximum text length in bytes before a [`FlagKind::TooLong`] flag.
pub const DEFAULT_MAX_LEN: usize = 4000;
const MIN_BASE64_RUN: usize = 24;
const MIN_HEX_RUN: usize = 32;
const MIN_LONG_NUMBER_DIGITS: usize = 9;
const MIN_CANARY_CHARS: usize = 8;
const SHINGLE_WORDS: usize = 5;

/// Kind of a risk flag shown on the owner's approval screen. Never shown to the agent (SP-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FlagKind {
    /// URL, scheme link or e-mail address.
    Link,
    /// Long base64-looking run.
    Base64Blob,
    /// Long hex run.
    HexBlob,
    /// Long digit run (phones, ids, account numbers).
    LongNumber,
    /// Luhn-valid card number.
    CardNumber,
    /// Checksum-valid IBAN.
    Iban,
    /// API key, token or private key.
    Secret,
    /// One-time code, 2FA or OTP secret.
    OneTimeCode,
    /// The exact value of a named vault secret.
    VaultSecret,
    /// Link that grants access to whoever holds it.
    PrivateLink,
    /// Invisible, bidirectional or control character.
    InvisibleChar,
    /// Text longer than the A1 prompt capacity.
    TooLong,
    /// Has attachments.
    Attachment,
    /// Recipient never received anything before.
    NewRecipient,
    /// Owner dictionary term.
    Dictionary,
    /// Near-verbatim match of a registered source's fingerprint.
    Fingerprint,
    /// Registered source read during the peer turn.
    SourceRead,
    /// A fuzzy check raised the level.
    Fuzzy,
    /// The tenant is in tripwire mode.
    Tripwire,
    /// Owner canary marker. Always blocks.
    Canary,
}

/// A risk flag with the byte range it covers in the text, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flag {
    /// Kind.
    pub kind: FlagKind,
    /// Byte offset of the match start.
    pub start: Option<usize>,
    /// Byte offset of the match end.
    pub end: Option<usize>,
    /// Short owner-facing detail; never the matched secret itself.
    pub detail: String,
    /// The registry source the match belongs to, for stages S4, S5, S8 and S9.
    pub source: Option<Source>,
}

/// Requirement for releasing a draft. Ordered by friction; [`Required::Block`] is the top.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Required {
    /// The owner must approve at this level or above.
    Level(Level),
    /// Nothing can release it, approval included.
    Block,
}

/// Result of [`assess`]: the requirement and the flags behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// Requirement after every check.
    pub required: Required,
    /// Flags for the owner's approval screen.
    pub flags: Vec<Flag>,
    /// Hits on sources the registry allows towards the recipient: shown to the owner, no floor,
    /// no flag for S12.
    pub allowed: Vec<Flag>,
    /// Canaries found, by id, in settings order; empty when none matched.
    pub canaries: Vec<CanaryId>,
}

impl Assessment {
    /// Raises the requirement to at least `r`. There is no way to lower it.
    pub fn raise(&mut self, r: Required) {
        self.required = self.required.max(r);
    }

    fn flag(&mut self, f: Flag, floor: Level) {
        self.flags.push(f);
        self.raise(Required::Level(floor));
    }

    /// A hit on `source`: Allow records it only, Ask raises to the stage `floor`, Never blocks.
    fn source_hit(&mut self, decisions: &Decisions, f: Flag, source: Source, floor: Level) {
        let f = Flag {
            source: Some(source),
            ..f
        };
        match decisions.access(source) {
            Access::Allow => self.allowed.push(f),
            Access::Ask => self.flag(f, floor),
            Access::Never => {
                self.flags.push(f);
                self.raise(Required::Block);
            }
        }
    }
}

/// What the draft is, which sets the base requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputKind {
    /// Free text: base A1 (S1).
    FreeText,
    /// A rendered owner template: no base floor; still A1 without an open mandate.
    Template,
    /// A shelf share read by the gate: no base floor; still A1 without an open mandate.
    Share,
}

/// A read of a registered source during the peer-started turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRead {
    /// The source read.
    pub source: SourceId,
    /// Whether the read is in the gate's own MCP log rather than claimed by the agent.
    pub verified: bool,
}

/// The owner's gate-side configuration. The agent can neither read nor edit it. Its `Debug`
/// output names canaries by id and never shows a marker.
#[derive(Clone, Default)]
pub struct OwnerRules {
    /// Dictionary terms, folded.
    dictionary: Vec<Vec<char>>,
    /// Canary markers, normalised, with their ids.
    canaries: Vec<(CanaryId, String)>,
    /// Shingle sets of registered sources' documents.
    fingerprints: Vec<(SourceId, BTreeSet<u64>)>,
    /// Named vault secrets.
    vault: Vec<sources::VaultSecret>,
    /// Private link entries added to [`DEFAULT_PRIVATE_LINK_DOMAINS`].
    private_link_domains: Vec<String>,
    /// Maximum length before a flag; [`DEFAULT_MAX_LEN`] when zero.
    pub max_len: usize,
}

impl fmt::Debug for OwnerRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let canaries: Vec<CanaryId> = self.canaries.iter().map(|(id, _)| *id).collect();
        f.debug_struct("OwnerRules")
            .field("dictionary", &self.dictionary)
            .field("canaries", &canaries)
            .field("fingerprints", &self.fingerprints)
            .field("vault", &self.vault)
            .field("private_link_domains", &self.private_link_domains)
            .field("max_len", &self.max_len)
            .finish()
    }
}

/// The gate's id of one canary marker in a tenant's settings. Notices and the journal name a
/// canary by this id, never by its marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanaryId(pub u32);

/// A canary marker too short to be unique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryTooShort;

impl OwnerRules {
    /// Adds a dictionary term (names, diagnoses, companies, topics).
    pub fn add_term(&mut self, term: &str) {
        let folded: Vec<char> = term.chars().map(fold).collect();
        if !folded.is_empty() {
            self.dictionary.push(folded);
        }
    }

    /// Adds `marker` as canary `id`. Matching ignores case, punctuation and whitespace.
    ///
    /// # Errors
    /// [`CanaryTooShort`] when fewer than 8 letters or digits remain after normalisation.
    pub fn add_canary(&mut self, id: CanaryId, marker: &str) -> Result<(), CanaryTooShort> {
        let n = normalise(marker);
        if n.chars().count() < MIN_CANARY_CHARS {
            return Err(CanaryTooShort);
        }
        self.canaries.push((id, n));
        Ok(())
    }

    /// Fingerprints `document` of registered source `source` for near-verbatim detection.
    pub fn add_fingerprint(&mut self, source: SourceId, document: &str) {
        let s = shingles(document);
        if !s.is_empty() {
            self.fingerprints.push((source, s));
        }
    }
}

/// Everything [`assess`] looks at for one draft.
#[derive(Debug, Clone, Copy)]
pub struct Draft<'a> {
    /// Exact text.
    pub text: &'a str,
    /// Kind of output.
    pub kind: OutputKind,
    /// Number of attachments.
    pub attachments: usize,
    /// Text of the attachments, searched for vault secrets and canaries.
    pub attachment_text: &'a [&'a str],
    /// Whether the recipient never received anything before.
    pub new_recipient: bool,
    /// Sources read during the turn.
    pub sources: &'a [SourceRead],
    /// The source registry's decisions towards the recipient.
    pub decisions: &'a Decisions,
    /// Level suggested by a fuzzy check (embeddings, classifier). Can only raise, to A2 at most.
    pub fuzzy_hint: Option<Level>,
    /// Whether tripwire mode is in effect for the tenant (S11,
    /// [`crate::tripwire::TripwireBook::in_effect`]).
    pub tripwire: bool,
    /// Whether an active open mandate matches this revision (S12).
    pub open_mandate: bool,
}

/// Evaluates `d` against `rules`.
pub fn assess(rules: &OwnerRules, d: &Draft<'_>) -> Assessment {
    let base = match d.kind {
        OutputKind::FreeText => Level::A1,
        OutputKind::Template | OutputKind::Share => Level::A0,
    };
    let mut a = Assessment {
        required: Required::Level(base),
        flags: Vec::new(),
        allowed: Vec::new(),
        canaries: canary_hits(rules, d.text, d.attachment_text),
    };
    for f in structural(d.text)
        .into_iter()
        .chain(rules.private_links(d.text))
    {
        match builtin_source(f.kind) {
            Some(b) => a.source_hit(d.decisions, f, Source::BuiltIn(b), Level::A2),
            None => a.flag(f, Level::A2),
        }
    }
    let max_len = if rules.max_len == 0 {
        DEFAULT_MAX_LEN
    } else {
        rules.max_len
    };
    if d.text.len() > max_len {
        let f = flag(FlagKind::TooLong, None, format!("{} bytes", d.text.len()));
        a.flag(f, Level::A2);
    }
    if d.attachments > 0 {
        let f = flag(
            FlagKind::Attachment,
            None,
            format!("{} attachment(s)", d.attachments),
        );
        a.flag(f, Level::A2);
    }
    if d.new_recipient {
        a.flag(flag(FlagKind::NewRecipient, None, String::new()), Level::A2);
    }
    for (id, range) in rules.vault_hits(d.text, d.attachment_text) {
        let f = flag(FlagKind::VaultSecret, range, String::new());
        a.source_hit(d.decisions, f, Source::Registered(id), Level::A2);
    }
    for f in dictionary_hits(rules, d.text) {
        a.flag(f, Level::A2);
    }
    for id in fingerprint_hits(rules, d.text) {
        let f = flag(FlagKind::Fingerprint, None, String::new());
        a.source_hit(d.decisions, f, Source::Registered(id), Level::A2Plus);
    }
    let mut reads: BTreeMap<SourceId, bool> = BTreeMap::new();
    for r in d.sources {
        *reads.entry(r.source).or_default() |= r.verified;
    }
    for (id, verified) in reads {
        let detail = if verified {
            "per gate MCP log"
        } else {
            "agent says"
        };
        let f = flag(FlagKind::SourceRead, None, detail.into());
        a.source_hit(d.decisions, f, Source::Registered(id), Level::A2Plus);
    }
    if let Some(hint) = d.fuzzy_hint.filter(|&h| h > Level::A0) {
        let capped = hint.min(Level::A2);
        a.flag(flag(FlagKind::Fuzzy, None, capped.to_string()), capped);
    }
    if d.tripwire {
        let f = flag(FlagKind::Tripwire, None, String::new());
        a.flag(f, crate::tripwire::TRIPWIRE_LEVEL);
    }
    if !a.canaries.is_empty() {
        a.flags.push(flag(FlagKind::Canary, None, String::new()));
        a.raise(Required::Block);
    }
    if d.open_mandate && a.flags.is_empty() {
        a.required = Required::Level(Level::A0);
    } else {
        a.raise(Required::Level(Level::A1));
    }
    a
}

fn flag(kind: FlagKind, range: Option<(usize, usize)>, detail: String) -> Flag {
    Flag {
        kind,
        start: range.map(|r| r.0),
        end: range.map(|r| r.1),
        detail,
        source: None,
    }
}

/// The built-in registry source of a flag: S4 secrets, one-time codes and private links, and S5
/// personal identifiers.
fn builtin_source(kind: FlagKind) -> Option<BuiltIn> {
    match kind {
        FlagKind::Secret => Some(BuiltIn::Secrets),
        FlagKind::OneTimeCode => Some(BuiltIn::OneTimeCodes),
        FlagKind::PrivateLink => Some(BuiltIn::PrivateLinks),
        FlagKind::CardNumber | FlagKind::Iban => Some(BuiltIn::PersonalIds),
        _ => None,
    }
}

/// Exact structural detectors: links, encoded blobs, long numbers, cards, IBANs, secrets,
/// one-time codes and invisible characters.
pub fn structural(text: &str) -> Vec<Flag> {
    let mut out = Vec::new();
    links(text, &mut out);
    blobs(text, &mut out);
    numbers(text, &mut out);
    ibans(text, &mut out);
    secrets(text, &mut out);
    sources::one_time_codes(text, &mut out);
    for (i, c) in text.char_indices() {
        if is_invisible(c) {
            out.push(flag(
                FlagKind::InvisibleChar,
                Some((i, i + c.len_utf8())),
                format!("U+{:04X}", c as u32),
            ));
        }
    }
    out
}

fn is_invisible(c: char) -> bool {
    (c.is_control() && c != '\t' && c != '\n')
        || matches!(c as u32,
        0x00AD | 0x180E | 0x200B..=0x200F | 0x2028..=0x202E | 0x2060..=0x2064 | 0x2066..=0x2069
        | 0xFEFF | 0xE0000..=0xE007F)
}

/// Maximal runs of characters satisfying `pred`, as byte ranges.
fn runs(text: &str, pred: impl Fn(char) -> bool) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices() {
        match (pred(c), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                out.push((s, i));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push((s, text.len()));
    }
    out
}

fn words(text: &str) -> Vec<(usize, usize)> {
    runs(text, |c| {
        !c.is_whitespace()
            && !matches!(
                c,
                '"' | '\'' | '`' | '(' | ')' | '<' | '>' | '[' | ']' | ','
            )
    })
}

/// Byte ranges of the words that are URLs, scheme links, e-mail addresses or host/path links.
fn link_words(text: &str) -> Vec<(usize, usize)> {
    words(text)
        .into_iter()
        .filter(|&(s, e)| {
            let w = text[s..e].to_ascii_lowercase();
            let schemed = w.contains("://")
                || w.starts_with("www.")
                || ["mailto:", "data:", "javascript:", "file:"]
                    .iter()
                    .any(|p| w.contains(p));
            let host_path = w.split_once('/').is_some_and(|(host, _)| {
                host.rsplit_once('.').is_some_and(|(left, tld)| {
                    !left.is_empty()
                        && (2..=24).contains(&tld.len())
                        && tld.bytes().all(|b| b.is_ascii_lowercase())
                })
            });
            schemed || host_path
        })
        .collect()
}

fn links(text: &str, out: &mut Vec<Flag>) {
    for range in link_words(text) {
        out.push(flag(FlagKind::Link, Some(range), String::new()));
    }
}

fn blobs(text: &str, out: &mut Vec<Flag>) {
    for (s, e) in runs(text, |c| c.is_ascii_hexdigit()) {
        if e - s >= MIN_HEX_RUN {
            out.push(flag(
                FlagKind::HexBlob,
                Some((s, e)),
                format!("{} chars", e - s),
            ));
        }
    }
    for (s, e) in runs(text, is_b64) {
        let run = &text[s..e];
        let classes = [
            run.bytes().any(|b| b.is_ascii_uppercase()),
            run.bytes().any(|b| b.is_ascii_lowercase()),
            run.bytes().any(|b| b.is_ascii_digit()),
        ];
        if e - s >= MIN_BASE64_RUN
            && classes.iter().filter(|x| **x).count() >= 2
            && !run.bytes().all(|b| b.is_ascii_hexdigit())
        {
            out.push(flag(
                FlagKind::Base64Blob,
                Some((s, e)),
                format!("{} chars", e - s),
            ));
        }
    }
}

fn is_b64(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_')
}

fn numbers(text: &str, out: &mut Vec<Flag>) {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = if i > 0 && b[i - 1] == b'+' { i - 1 } else { i };
        let mut digits = Vec::new();
        let mut end = i;
        while end < b.len() {
            if b[end].is_ascii_digit() {
                digits.push(b[end] - b'0');
                end += 1;
            } else if matches!(b[end], b' ' | b'-' | b'.')
                && end + 1 < b.len()
                && b[end + 1].is_ascii_digit()
            {
                end += 1;
            } else {
                break;
            }
        }
        if digits.len() >= MIN_LONG_NUMBER_DIGITS {
            let kind = if (13..=19).contains(&digits.len()) && luhn(&digits) {
                FlagKind::CardNumber
            } else {
                FlagKind::LongNumber
            };
            out.push(flag(
                kind,
                Some((start, end)),
                format!("{} digits", digits.len()),
            ));
        }
        i = end;
    }
}

fn luhn(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            let d = u32::from(d);
            if i % 2 == 1 {
                if d * 2 > 9 { d * 2 - 9 } else { d * 2 }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

fn ibans(text: &str, out: &mut Vec<Flag>) {
    let up = text.to_ascii_uppercase();
    let b = up.as_bytes();
    let mut i = 0;
    while i + 4 <= b.len() {
        let starts = b[i].is_ascii_uppercase()
            && b[i + 1].is_ascii_uppercase()
            && b[i + 2].is_ascii_digit()
            && b[i + 3].is_ascii_digit()
            && (i == 0 || !b[i - 1].is_ascii_alphanumeric());
        if !starts {
            i += 1;
            continue;
        }
        let mut chars = Vec::new();
        let mut ends = Vec::new();
        let mut j = i;
        while j < b.len() && chars.len() < 34 {
            if b[j].is_ascii_alphanumeric() {
                chars.push(b[j]);
                ends.push(j + 1);
                j += 1;
            } else if b[j] == b' ' && j + 1 < b.len() && b[j + 1].is_ascii_alphanumeric() {
                j += 1;
            } else {
                break;
            }
        }
        match (15..=chars.len()).rev().find(|&n| iban_valid(&chars[..n])) {
            Some(n) => {
                out.push(flag(FlagKind::Iban, Some((i, ends[n - 1])), String::new()));
                i = ends[n - 1];
            }
            None => i += 1,
        }
    }
}

fn iban_valid(s: &[u8]) -> bool {
    let mut rem: u32 = 0;
    for &c in s[4..].iter().chain(&s[..4]) {
        let v = if c.is_ascii_digit() {
            u32::from(c - b'0')
        } else {
            u32::from(c - b'A') + 10
        };
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    rem == 1
}

fn secrets(text: &str, out: &mut Vec<Flag>) {
    const PREFIXES: [(&str, usize); 17] = [
        ("sk-", 20),
        ("ghp_", 36),
        ("gho_", 36),
        ("ghu_", 36),
        ("ghs_", 36),
        ("ghr_", 36),
        ("github_pat_", 40),
        ("xoxb-", 20),
        ("xoxp-", 20),
        ("xoxa-", 20),
        ("xoxs-", 20),
        ("AKIA", 20),
        ("ASIA", 20),
        ("AIza", 39),
        ("glpat-", 20),
        ("npm_", 36),
        ("pypi-", 40),
    ];
    for (s, e) in words(text) {
        let w = &text[s..e];
        let prefixed = PREFIXES
            .iter()
            .any(|(p, min)| w.starts_with(p) && w.len() >= *min);
        let jwt = w.starts_with("eyJ") && w.len() >= 30 && w.matches('.').count() == 2;
        if prefixed || jwt {
            out.push(flag(FlagKind::Secret, Some((s, e)), "token".into()));
        }
    }
    if let Some(s) = text.find("-----BEGIN") {
        if text[s..].contains("PRIVATE KEY") {
            out.push(flag(
                FlagKind::Secret,
                Some((s, text.len())),
                "private key".into(),
            ));
        }
    }
}

fn fold(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

fn normalise(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .map(fold)
        .collect()
}

fn dictionary_hits(rules: &OwnerRules, text: &str) -> Vec<Flag> {
    let chars: Vec<(usize, char)> = text.char_indices().map(|(i, c)| (i, fold(c))).collect();
    let mut out = Vec::new();
    for term in &rules.dictionary {
        for w in 0..chars.len().saturating_sub(term.len() - 1) {
            if chars[w..w + term.len()]
                .iter()
                .map(|x| x.1)
                .eq(term.iter().copied())
            {
                let (last_i, last_c) = chars[w + term.len() - 1];
                let end = last_i
                    + text[last_i..]
                        .chars()
                        .next()
                        .map_or(last_c.len_utf8(), char::len_utf8);
                out.push(flag(
                    FlagKind::Dictionary,
                    Some((chars[w].0, end)),
                    term.iter().collect(),
                ));
            }
        }
    }
    out
}

/// Canary search over the body, the attachment texts and their decoded base64/hex runs, ignoring
/// case and separators.
fn canary_hits(rules: &OwnerRules, body: &str, attachment_text: &[&str]) -> Vec<CanaryId> {
    if rules.canaries.is_empty() {
        return Vec::new();
    }
    let haystacks: Vec<String> = std::iter::once(body)
        .chain(attachment_text.iter().copied())
        .flat_map(canary_haystacks)
        .collect();
    rules
        .canaries
        .iter()
        .filter(|(_, c)| haystacks.iter().any(|h| h.contains(c.as_str())))
        .map(|(id, _)| *id)
        .collect()
}

/// `text` and its decoded base64/hex runs, normalised.
fn canary_haystacks(text: &str) -> Vec<String> {
    let mut haystacks = vec![normalise(text)];
    for (s, e) in runs(text, is_b64) {
        let run = text[s..e].trim_end_matches('=');
        for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
            if let Ok(bytes) = engine.decode(run) {
                haystacks.push(normalise(&String::from_utf8_lossy(&bytes)));
            }
        }
        if run.len() % 2 == 0 && run.bytes().all(|b| b.is_ascii_hexdigit()) {
            let bytes: Vec<u8> = run
                .as_bytes()
                .chunks_exact(2)
                .filter_map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
                .collect();
            haystacks.push(normalise(&String::from_utf8_lossy(&bytes)));
        }
    }
    haystacks
}

fn shingles(text: &str) -> BTreeSet<u64> {
    let words: Vec<String> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.chars().map(fold).collect())
        .collect();
    words
        .windows(SHINGLE_WORDS)
        .map(|win| {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for w in win {
                for b in w.bytes().chain([0]) {
                    h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
                }
            }
            h
        })
        .collect()
}

/// Sources with a near-verbatim document: at least 3 shared shingles, and either 8 shared or
/// half of the text's own. Each source once, in registration order.
fn fingerprint_hits(rules: &OwnerRules, text: &str) -> Vec<SourceId> {
    let s = shingles(text);
    let mut out: Vec<SourceId> = Vec::new();
    for (id, d) in &rules.fingerprints {
        let shared = s.intersection(d).count();
        if shared >= 3 && (shared >= 8 || shared * 2 >= s.len()) && !out.contains(id) {
            out.push(*id);
        }
    }
    out
}

#[cfg(test)]
mod tests;
