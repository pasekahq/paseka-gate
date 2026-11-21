//! Detectors of registry sources beyond the gitleaks-style rules: one-time codes, named vault
//! secrets and private links (PROTOCOL §6.4).

use std::fmt;

use super::{Flag, FlagKind, OwnerRules, flag, link_words, runs, words};
use crate::source::SourceId;

/// Minimum length in characters of a vault secret value.
pub const MIN_VAULT_SECRET_CHARS: usize = 8;

/// Entries of the built-in private links source: a host, which also covers its subdomains, with
/// an optional path prefix.
pub const DEFAULT_PRIVATE_LINK_DOMAINS: [&str; 17] = [
    "docs.google.com",
    "drive.google.com",
    "dropbox.com",
    "1drv.ms",
    "onedrive.live.com",
    "sharepoint.com",
    "box.com",
    "icloud.com/share",
    "wetransfer.com",
    "we.tl",
    "t.me/+",
    "t.me/joinchat",
    "chat.whatsapp.com",
    "discord.gg",
    "discord.com/invite",
    "join.slack.com",
    "zoom.us/j",
];

/// Query and fragment parameters that carry access by possession. A name ending in `token` or
/// `signature` counts too.
const LINK_TOKEN_PARAMS: [&str; 17] = [
    "sig",
    "signature",
    "token",
    "auth",
    "key",
    "api_key",
    "apikey",
    "secret",
    "password",
    "pwd",
    "code",
    "otp",
    "invite",
    "magic",
    "x-amz-credential",
    "x-goog-credential",
    "googleaccessid",
];

const CODE_DIGITS: std::ops::RangeInclusive<usize> = 4..=8;
const CODE_GROUP_DIGITS: std::ops::RangeInclusive<usize> = 3..=4;
/// Words between a code and its keyword, at most.
const CODE_KEYWORD_WINDOW: usize = 4;
const CODE_KEYWORDS: [&str; 19] = [
    "code",
    "codes",
    "otp",
    "2fa",
    "mfa",
    "totp",
    "passcode",
    "verification",
    "verify",
    "one-time",
    "код",
    "кода",
    "коду",
    "кодом",
    "коде",
    "коды",
    "кодов",
    "отп",
    "2фа",
];
const CODE_KEYWORD_STEMS: [&str; 3] = ["подтвержд", "верификац", "одноразов"];
/// Words that, next to a keyword, name a code that grants nothing.
const CODE_QUALIFIERS: [&str; 17] = [
    "zip",
    "postal",
    "post",
    "area",
    "country",
    "error",
    "exit",
    "status",
    "source",
    "promo",
    "discount",
    "coupon",
    "почтовый",
    "ошибки",
    "региона",
    "страны",
    "города",
];

/// A vault secret value too short to match only itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultSecretTooShort;

/// A named vault secret. Its `Debug` output never shows the value.
#[derive(Clone)]
pub(super) struct VaultSecret {
    source: SourceId,
    value: String,
}

impl fmt::Debug for VaultSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSecret")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl OwnerRules {
    /// Adds `value` of named vault secret `source`. Matching is exact and case-sensitive.
    ///
    /// # Errors
    /// [`VaultSecretTooShort`] when `value` has fewer than [`MIN_VAULT_SECRET_CHARS`] characters.
    pub fn add_vault_secret(
        &mut self,
        source: SourceId,
        value: &str,
    ) -> Result<(), VaultSecretTooShort> {
        if value.chars().count() < MIN_VAULT_SECRET_CHARS {
            return Err(VaultSecretTooShort);
        }
        self.vault.push(VaultSecret {
            source,
            value: value.into(),
        });
        Ok(())
    }

    /// Adds `entry`, a host with an optional path prefix, to the private links source.
    pub fn add_private_link_domain(&mut self, entry: &str) {
        let entry = entry.trim().to_ascii_lowercase();
        if !entry.is_empty() {
            self.private_link_domains.push(entry);
        }
    }

    /// Vault sources whose value occurs in `text` or in an attachment's text, each once in
    /// registration order, with the first range in `text` if any.
    pub(super) fn vault_hits(
        &self,
        text: &str,
        attachment_text: &[&str],
    ) -> Vec<(SourceId, Option<(usize, usize)>)> {
        let mut out: Vec<(SourceId, Option<(usize, usize)>)> = Vec::new();
        for v in &self.vault {
            if out.iter().any(|(id, _)| *id == v.source) {
                continue;
            }
            let v_len = v.value.len();
            if let Some(i) = text.find(&v.value) {
                out.push((v.source, Some((i, i + v_len))));
            } else if attachment_text.iter().any(|t| t.contains(&v.value)) {
                out.push((v.source, None));
            }
        }
        out
    }

    /// Links to a private link domain or with an access token in the query or fragment.
    pub(super) fn private_links(&self, text: &str) -> Vec<Flag> {
        let entries = DEFAULT_PRIVATE_LINK_DOMAINS
            .iter()
            .copied()
            .chain(self.private_link_domains.iter().map(String::as_str));
        let entries: Vec<&str> = entries.collect();
        let mut out = Vec::new();
        for (s, e) in link_words(text) {
            let w = text[s..e].to_ascii_lowercase();
            let link = Link::parse(&w);
            let detail = entries
                .iter()
                .find(|entry| link.under(entry))
                .map(|entry| (*entry).to_string())
                .or_else(|| link.token_param().map(|p| format!("{p} in the query")));
            if let Some(detail) = detail {
                out.push(flag(FlagKind::PrivateLink, Some((s, e)), detail));
            }
        }
        out
    }
}

/// The parts of a lowercased link word that decide whether it is private.
struct Link<'a> {
    host: &'a str,
    path: &'a str,
    params: &'a str,
}

impl<'a> Link<'a> {
    fn parse(w: &'a str) -> Self {
        let rest = w.split_once("://").map_or(w, |(_, r)| r);
        let (authority, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
        let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let host = host.split_once(':').map_or(host, |(h, _)| h);
        let (path, params) = tail.split_at(tail.find(['?', '#']).unwrap_or(tail.len()));
        Self { host, path, params }
    }

    /// Whether the link is on `entry`'s host or a subdomain of it, under its path prefix.
    fn under(&self, entry: &str) -> bool {
        let (host, prefix) = entry.split_once('/').unwrap_or((entry, ""));
        let on_host = self.host == host
            || self
                .host
                .strip_suffix(host)
                .is_some_and(|sub| sub.ends_with('.'));
        on_host
            && self
                .path
                .strip_prefix('/')
                .unwrap_or(self.path)
                .starts_with(prefix)
    }

    /// The first query or fragment parameter that carries access and has a value.
    fn token_param(&self) -> Option<&'a str> {
        self.params
            .split(['?', '#', '&', ';'])
            .filter_map(|p| p.split_once('='))
            .filter(|(_, value)| !value.is_empty())
            .map(|(name, _)| name)
            .find(|name| {
                LINK_TOKEN_PARAMS.contains(name)
                    || name.ends_with("token")
                    || name.ends_with("signature")
            })
    }
}

/// One-time codes: a code of 4 to 8 digits that is not a year, or two groups of 3 or 4, within
/// [`CODE_KEYWORD_WINDOW`] words of a code keyword; and `otpauth:` URIs.
pub(super) fn one_time_codes(text: &str, out: &mut Vec<Flag>) {
    for (s, e) in words(text) {
        if text[s..e].to_ascii_lowercase().contains("otpauth:") {
            out.push(flag(
                FlagKind::OneTimeCode,
                Some((s, e)),
                "otpauth URI".into(),
            ));
        }
    }
    let tokens = code_tokens(text);
    let digits = |i: usize| tokens.get(i).is_some_and(|t| all_digits(&t.word));
    let spaced = |i: usize| {
        tokens
            .get(i + 1)
            .is_some_and(|n| &text[tokens[i].end..n.start] == " ")
    };
    let mut i = 0;
    while i < tokens.len() {
        let t = &tokens[i];
        let pair = digits(i)
            && digits(i + 1)
            && spaced(i)
            && CODE_GROUP_DIGITS.contains(&t.word.len())
            && CODE_GROUP_DIGITS.contains(&tokens[i + 1].word.len());
        let last = if pair { i + 1 } else { i };
        let single = !pair && (code_digits(&t.word) || grouped(&t.word));
        let digits_before = i > 0 && digits(i - 1) && spaced(i - 1);
        let digits_after = digits(last + 1) && spaced(last);
        let isolated = !(digits_before || digits_after);
        if (pair || single) && isolated && near_keyword(&tokens, i, last) {
            let range = (t.start, tokens[last].end);
            out.push(flag(FlagKind::OneTimeCode, Some(range), "code".into()));
        }
        i = last + 1;
    }
}

struct Token {
    start: usize,
    end: usize,
    word: String,
}

/// Words split at whitespace and at `:;,()[]{}"'«»`, without trailing `.!?`, lowercased.
fn code_tokens(text: &str) -> Vec<Token> {
    let sep = |c: char| c.is_whitespace() || ":;,()[]{}\"'«»".contains(c);
    runs(text, |c| !sep(c))
        .into_iter()
        .filter_map(|(start, end)| {
            let trimmed = text[start..end].trim_end_matches(['.', '!', '?']);
            (!trimmed.is_empty()).then(|| Token {
                start,
                end: start + trimmed.len(),
                word: trimmed.to_lowercase(),
            })
        })
        .collect()
}

fn all_digits(w: &str) -> bool {
    !w.is_empty() && w.bytes().all(|b| b.is_ascii_digit())
}

/// 4 to 8 digits, except a year from 1900 to 2099.
fn code_digits(w: &str) -> bool {
    let year = w.len() == 4 && (w.starts_with("19") || w.starts_with("20"));
    all_digits(w) && CODE_DIGITS.contains(&w.len()) && !year
}

/// `123-456` or `1234-5678`.
fn grouped(w: &str) -> bool {
    w.split_once('-').is_some_and(|(a, b)| {
        [a, b]
            .iter()
            .all(|g| all_digits(g) && CODE_GROUP_DIGITS.contains(&g.len()))
    })
}

fn near_keyword(tokens: &[Token], first: usize, last: usize) -> bool {
    let before = first.saturating_sub(CODE_KEYWORD_WINDOW)..first;
    let after = last + 1..(last + 1 + CODE_KEYWORD_WINDOW).min(tokens.len());
    before.chain(after).any(|k| keyword(tokens, k))
}

fn keyword(tokens: &[Token], k: usize) -> bool {
    let w = tokens[k].word.as_str();
    let named = CODE_KEYWORDS.contains(&w) || CODE_KEYWORD_STEMS.iter().any(|s| w.starts_with(s));
    let qualified = [k.checked_sub(1), Some(k + 1)]
        .into_iter()
        .flatten()
        .filter_map(|n| tokens.get(n))
        .any(|n| CODE_QUALIFIERS.contains(&n.word.as_str()));
    named && !qualified
}
