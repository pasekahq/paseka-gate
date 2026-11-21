//! Telegram Mini App `initData`: the Ed25519 third-party signature (PROTOCOL §7.4 steps 1 to 3)
//! and freshness (step 5).

use std::collections::BTreeMap;
use std::ops::RangeInclusive;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use paseka_proto::evidence::TelegramEnv;
use paseka_proto::{Sha256, UnixSecs};

/// Telegram's production Ed25519 key for initData, as published in the Mini Apps documentation,
/// section "Validating data for Third-Party Use". The default of the production key setting.
pub const TELEGRAM_PRODUCTION_KEY_HEX: &str =
    "e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d";
/// Telegram's test environment Ed25519 key for initData, from the same section. The default of
/// the test key setting.
pub const TELEGRAM_TEST_KEY_HEX: &str =
    "40055058a4ee38156a06562e52eece92a771bcd8346a8c4615cb7376eddf72ec";

/// Fields step 1 requires.
const REQUIRED: [&str; 4] = ["auth_date", "hash", "signature", "user"];

/// Why initData or a Telegram key setting was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitDataError {
    /// Not `application/x-www-form-urlencoded` UTF-8: an empty pair, a pair without `=`, a bad
    /// percent escape, or an `auth_date` that is not Unix seconds.
    Malformed,
    /// A key occurs twice, compared after decoding.
    DuplicateKey(String),
    /// A field step 1 requires is absent.
    Missing(&'static str),
    /// `signature` is not b64u of 64 bytes or does not verify.
    BadSignature,
    /// A key setting is not 64 lowercase hex characters of an Ed25519 point.
    BadKey,
    /// The configured environment is one this build does not know.
    UnknownEnvironment,
}

/// Telegram's initData keys per environment, a security setting (§9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelegramKeys {
    production: VerifyingKey,
    test: VerifyingKey,
}

impl TelegramKeys {
    /// Keys from their hex settings.
    ///
    /// # Errors
    /// [`InitDataError::BadKey`] when either is not a hex Ed25519 point.
    pub fn from_hex(production: &str, test: &str) -> Result<Self, InitDataError> {
        Ok(Self::new(key_from_hex(production)?, key_from_hex(test)?))
    }

    /// Keys from verifying keys.
    pub fn new(production: VerifyingKey, test: VerifyingKey) -> Self {
        Self { production, test }
    }

    /// The key that verifies initData of the configured environment `env`.
    ///
    /// # Errors
    /// [`InitDataError::UnknownEnvironment`] for [`TelegramEnv::Unknown`].
    pub fn key(&self, env: TelegramEnv) -> Result<&VerifyingKey, InitDataError> {
        match env {
            TelegramEnv::Production => Ok(&self.production),
            TelegramEnv::Test => Ok(&self.test),
            TelegramEnv::Unknown => Err(InitDataError::UnknownEnvironment),
        }
    }
}

impl Default for TelegramKeys {
    /// The documented keys.
    fn default() -> Self {
        Self::from_hex(TELEGRAM_PRODUCTION_KEY_HEX, TELEGRAM_TEST_KEY_HEX)
            .expect("the documented Telegram keys are Ed25519 points")
    }
}

fn key_from_hex(hex: &str) -> Result<VerifyingKey, InitDataError> {
    // A SHA-256 value is exactly 32 bytes of lowercase hex, the shape of a key setting.
    let bytes = Sha256::from_hex(hex).map_err(|_| InitDataError::BadKey)?.0;
    VerifyingKey::from_bytes(&bytes).map_err(|_| InitDataError::BadKey)
}

/// initData whose Ed25519 signature verified (PROTOCOL §7.4 steps 1 to 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitData {
    fields: BTreeMap<String, String>,
    auth_date: UnixSecs,
}

impl InitData {
    /// Parses `raw`, refusing duplicate keys and missing required fields, and verifies
    /// `signature` over `<bot_id>:WebAppData\n<data-check-string>` with `key`.
    ///
    /// # Errors
    /// [`InitDataError`] on the first failed step.
    pub fn verify(raw: &str, bot_id: i64, key: &VerifyingKey) -> Result<Self, InitDataError> {
        let fields = parse(raw)?;
        for name in REQUIRED {
            if !fields.contains_key(name) {
                return Err(InitDataError::Missing(name));
            }
        }
        let auth_date = fields["auth_date"]
            .parse()
            .map_err(|_| InitDataError::Malformed)?;
        let sig: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&fields["signature"])
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(InitDataError::BadSignature)?;
        let check = fields
            .iter()
            .filter(|(k, _)| *k != "hash" && *k != "signature")
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("\n");
        let message = format!("{bot_id}:WebAppData\n{check}");
        key.verify_strict(message.as_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| InitDataError::BadSignature)?;
        Ok(Self { fields, auth_date })
    }

    /// `auth_date`, for the freshness check of step 5.
    pub fn auth_date(&self) -> UnixSecs {
        self.auth_date
    }

    /// The decoded value of field `name`.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }
}

fn parse(raw: &str) -> Result<BTreeMap<String, String>, InitDataError> {
    let mut fields = BTreeMap::new();
    for pair in raw.split('&') {
        let (k, v) = pair.split_once('=').ok_or(InitDataError::Malformed)?;
        let k = decode(k)?;
        if k.is_empty() {
            return Err(InitDataError::Malformed);
        }
        if fields.contains_key(&k) {
            return Err(InitDataError::DuplicateKey(k));
        }
        fields.insert(k, decode(v)?);
    }
    Ok(fields)
}

/// Decodes one form-urlencoded component: `+` is a space, `%XX` a byte, the result UTF-8.
fn decode(s: &str) -> Result<String, InitDataError> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let byte = b
                    .get(i + 1..i + 3)
                    .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                    .and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok())
                    .ok_or(InitDataError::Malformed)?;
                out.push(byte);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).map_err(|_| InitDataError::Malformed)
}

/// Default initData window: the oldest accepted `auth_date` is this far before `now` (§14).
pub const INIT_DATA_WINDOW_DEFAULT: u64 = 300;
/// Allowed owner settings of the initData window (§14).
pub const INIT_DATA_WINDOW_RANGE: RangeInclusive<u64> = 60..=600;
/// How far after `now` an `auth_date` may lie (§14).
pub const INIT_DATA_FUTURE_SECS: u64 = 30;

/// An initData window setting outside [`INIT_DATA_WINDOW_RANGE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowOutOfRange(pub u64);

/// The owner's initData window, always in [`INIT_DATA_WINDOW_RANGE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitDataWindow {
    secs: u64,
}

impl InitDataWindow {
    /// A window of `secs`.
    ///
    /// # Errors
    /// [`WindowOutOfRange`] outside [`INIT_DATA_WINDOW_RANGE`].
    pub fn secs(secs: u64) -> Result<Self, WindowOutOfRange> {
        if INIT_DATA_WINDOW_RANGE.contains(&secs) {
            Ok(Self { secs })
        } else {
            Err(WindowOutOfRange(secs))
        }
    }

    /// Whether initData signed at `auth_date` is fresh at `now`: `now - auth_date <= window` and
    /// `auth_date <= now + INIT_DATA_FUTURE_SECS`.
    pub fn fresh(self, auth_date: UnixSecs, now: UnixSecs) -> bool {
        now.saturating_sub(auth_date) <= self.secs
            && auth_date <= now.saturating_add(INIT_DATA_FUTURE_SECS)
    }
}

impl Default for InitDataWindow {
    fn default() -> Self {
        Self {
            secs: INIT_DATA_WINDOW_DEFAULT,
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::Value;

    use super::*;
    use crate::testkit::{seed_key, vectors};

    const NOW: UnixSecs = 1_794_268_830;
    const TELEGRAM_VECTORS_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/fixtures/vectors/telegram-initdata.json"
    );
    const QUERY_ID: &str = "AAHdF6IQAAAAAN0XohDhrOrc";
    const USER: &str = r#"{"id":2000001,"first_name":"Alice","username":"alice"}"#;

    fn telegram_vectors() -> Value {
        serde_json::from_slice(&std::fs::read(TELEGRAM_VECTORS_PATH).unwrap()).unwrap()
    }

    fn encode(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    char::from(b).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }

    fn form(pairs: &[(&str, &str)]) -> String {
        pairs
            .iter()
            .map(|(k, v)| format!("{k}={}", encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// The documented example of the signed text, filled in and signed by `signer`.
    struct Example {
        bot_id: i64,
        signature: String,
        auth_date: String,
    }

    impl Example {
        fn signed_by(signer: &SigningKey) -> Self {
            let example = &telegram_vectors()["example"];
            let auth_date = (NOW - 20).to_string();
            let text = example["signed_text"]
                .as_str()
                .unwrap()
                .replace("<auth_date>", &auth_date)
                .replace("<query_id>", QUERY_ID)
                .replace("<user>", USER);
            Self {
                bot_id: example["bot_id"].as_i64().unwrap(),
                signature: URL_SAFE_NO_PAD.encode(signer.sign(text.as_bytes()).to_bytes()),
                auth_date,
            }
        }

        /// The initData fields, out of order, `hash` a stand-in for the HMAC of step 4.
        fn pairs(&self) -> Vec<(&str, &str)> {
            vec![
                ("user", USER),
                ("signature", &self.signature),
                ("query_id", QUERY_ID),
                ("hash", "00"),
                ("auth_date", &self.auth_date),
            ]
        }

        fn raw(&self) -> String {
            form(&self.pairs())
        }
    }

    fn alice() -> SigningKey {
        seed_key(&vectors(), "alice")
    }

    #[test]
    fn the_documented_keys_are_the_default_settings() {
        let keys = &telegram_vectors()["keys"];
        let documented = TelegramKeys::from_hex(
            keys["production"].as_str().unwrap(),
            keys["test"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(documented, TelegramKeys::default());
    }

    #[test]
    fn a_key_setting_must_be_a_hex_ed25519_point() {
        let upper = TELEGRAM_PRODUCTION_KEY_HEX.to_uppercase();
        for bad in [upper.as_str(), &TELEGRAM_TEST_KEY_HEX[2..], ""] {
            assert_eq!(
                TelegramKeys::from_hex(bad, TELEGRAM_TEST_KEY_HEX),
                Err(InitDataError::BadKey),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_documented_example_verifies_with_the_signers_key() {
        let ex = Example::signed_by(&alice());
        let data = InitData::verify(&ex.raw(), ex.bot_id, &alice().verifying_key()).unwrap();
        assert_eq!(data.auth_date(), NOW - 20);
        assert_eq!(data.field("user"), Some(USER));
        assert_eq!(data.field("query_id"), Some(QUERY_ID));
    }

    #[test]
    fn the_signature_covers_every_field_but_hash_and_signature() {
        let ex = Example::signed_by(&alice());
        let key = alice().verifying_key();
        let user = USER.replace("2000001", "2000002");
        let later = (NOW - 19).to_string();
        let changed: [(&str, &str); 4] = [
            ("user", &user),
            ("query_id", "AAHdF6IQAAAAAN0XohDhrOrd"),
            ("auth_date", &later),
            ("chat_type", "private"),
        ];
        for (name, value) in changed {
            let mut pairs = ex.pairs();
            pairs.retain(|(k, _)| *k != name);
            pairs.push((name, value));
            assert_eq!(
                InitData::verify(&form(&pairs), ex.bot_id, &key),
                Err(InitDataError::BadSignature),
                "{name}"
            );
        }
        let mut pairs = ex.pairs();
        pairs.retain(|(k, _)| *k != "hash");
        pairs.push(("hash", "ff"));
        assert!(InitData::verify(&form(&pairs), ex.bot_id, &key).is_ok());
        assert_eq!(
            InitData::verify(&ex.raw(), ex.bot_id + 1, &key),
            Err(InitDataError::BadSignature),
            "another bot id"
        );
    }

    #[test]
    fn a_duplicate_key_is_refused_before_any_signature_check() {
        let ex = Example::signed_by(&alice());
        let key = alice().verifying_key();
        for extra in ["&auth_date=1", "&%61uth_date=1", "&user=%7B%7D"] {
            let raw = format!("{}{extra}", ex.raw());
            assert!(
                matches!(
                    InitData::verify(&raw, ex.bot_id, &key),
                    Err(InitDataError::DuplicateKey(_))
                ),
                "{extra}"
            );
        }
    }

    #[test]
    fn each_required_field_must_be_present() {
        let ex = Example::signed_by(&alice());
        for name in REQUIRED {
            let mut pairs = ex.pairs();
            pairs.retain(|(k, _)| *k != name);
            assert_eq!(
                InitData::verify(&form(&pairs), ex.bot_id, &alice().verifying_key()),
                Err(InitDataError::Missing(name))
            );
        }
    }

    #[test]
    fn only_the_configured_environments_key_verifies() {
        let ex = Example::signed_by(&alice());
        let bob = seed_key(&vectors(), "bob").verifying_key();
        let keys = TelegramKeys::new(alice().verifying_key(), bob);
        let verify = |env| InitData::verify(&ex.raw(), ex.bot_id, keys.key(env)?);
        assert!(verify(TelegramEnv::Production).is_ok());
        assert_eq!(verify(TelegramEnv::Test), Err(InitDataError::BadSignature));
        assert_eq!(
            verify(TelegramEnv::Unknown),
            Err(InitDataError::UnknownEnvironment)
        );
        for env in [TelegramEnv::Production, TelegramEnv::Test] {
            let telegram = TelegramKeys::default();
            assert_eq!(
                InitData::verify(&ex.raw(), ex.bot_id, telegram.key(env).unwrap()),
                Err(InitDataError::BadSignature),
                "{env:?}"
            );
        }
    }

    #[test]
    fn malformed_encodings_are_refused() {
        let ex = Example::signed_by(&alice());
        let key = alice().verifying_key();
        let padded = format!("{}==", ex.signature);
        let cases: [(String, InitDataError); 7] = [
            (String::new(), InitDataError::Malformed),
            (format!("{}&&x=1", ex.raw()), InitDataError::Malformed),
            (format!("{}&x", ex.raw()), InitDataError::Malformed),
            (format!("{}&=1", ex.raw()), InitDataError::Malformed),
            (format!("{}&x=%2", ex.raw()), InitDataError::Malformed),
            (format!("{}&x=%+1", ex.raw()), InitDataError::Malformed),
            (
                form(&[
                    ("signature", &padded),
                    ("hash", "00"),
                    ("auth_date", "1"),
                    ("user", USER),
                ]),
                InitDataError::BadSignature,
            ),
        ];
        for (raw, want) in cases {
            assert_eq!(InitData::verify(&raw, ex.bot_id, &key), Err(want), "{raw}");
        }
        let mut pairs = ex.pairs();
        pairs.retain(|(k, _)| *k != "auth_date");
        pairs.push(("auth_date", "-1"));
        assert_eq!(
            InitData::verify(&form(&pairs), ex.bot_id, &key),
            Err(InitDataError::Malformed)
        );
        let invalid_utf8 = format!("{}&x=%FF", ex.raw());
        assert_eq!(
            InitData::verify(&invalid_utf8, ex.bot_id, &key),
            Err(InitDataError::Malformed)
        );
    }

    #[test]
    fn the_window_setting_is_bounded() {
        let (lo, hi) = (
            *INIT_DATA_WINDOW_RANGE.start(),
            *INIT_DATA_WINDOW_RANGE.end(),
        );
        for (secs, ok) in [(lo - 1, false), (lo, true), (hi, true), (hi + 1, false)] {
            assert_eq!(InitDataWindow::secs(secs).is_ok(), ok, "{secs} s");
        }
    }

    #[test]
    fn auth_date_is_fresh_inside_the_window_and_the_future_skew() {
        let w = InitDataWindow::default();
        let cases = [
            (NOW - INIT_DATA_WINDOW_DEFAULT - 1, false),
            (NOW - INIT_DATA_WINDOW_DEFAULT, true),
            (NOW, true),
            (NOW + INIT_DATA_FUTURE_SECS, true),
            (NOW + INIT_DATA_FUTURE_SECS + 1, false),
        ];
        for (auth_date, want) in cases {
            assert_eq!(w.fresh(auth_date, NOW), want, "auth_date {auth_date}");
        }
        let short = InitDataWindow::secs(60).unwrap();
        assert!(short.fresh(NOW - 60, NOW));
        assert!(!short.fresh(NOW - 61, NOW));
    }
}
