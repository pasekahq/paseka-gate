//! Approval channels and their evidence objects (PROTOCOL §6.3, §7; `contracts/evidence/`).

use serde::{Deserialize, Serialize};

use crate::{Level, MandateId, Nonce, RequestId, Sha256, TenantId, UnixSecs};

/// The approval channel that produced a consent. Authority-bearing: unknown values fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Channel {
    /// Owner-signed open mandate (A0).
    OpenMandate,
    /// Inline button in the gate's consent bot (A1).
    TelegramButton,
    /// Telegram Mini App with exact bytes (A2).
    #[serde(rename = "telegram-miniapp")]
    TelegramMiniApp,
    /// Telegram Mini App with exact bytes plus the owner's PIN or password (A2+).
    #[serde(rename = "telegram-miniapp-pin")]
    TelegramMiniAppPin,
    /// Mini App plus a biometric-unlocked key (A2+, later).
    #[serde(rename = "telegram-miniapp-biometric")]
    TelegramMiniAppBiometric,
    /// WebAuthn passkey in an external browser (A3, later).
    Passkey,
}

impl Channel {
    /// The strongest level this channel attests.
    pub fn strength(self) -> Level {
        match self {
            Self::OpenMandate => Level::A0,
            Self::TelegramButton => Level::A1,
            Self::TelegramMiniApp => Level::A2,
            Self::TelegramMiniAppPin | Self::TelegramMiniAppBiometric => Level::A2Plus,
            Self::Passkey => Level::A3,
        }
    }

    /// Whether this channel satisfies `level` (PROTOCOL §6.3). Only an open mandate satisfies
    /// A0, and an open mandate satisfies nothing else.
    pub fn satisfies(self, level: Level) -> bool {
        match (self, level) {
            (Self::OpenMandate, l) => l == Level::A0,
            (_, Level::A0) => false,
            (c, l) => c.strength() >= l,
        }
    }
}

/// The owner's decision. Authority-bearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Release this revision.
    Approve,
    /// Refuse it.
    Deny,
}

/// Telegram environment whose public key verified `initData`. Informational.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelegramEnv {
    /// Production Bot API.
    Production,
    /// Test environment.
    Test,
    /// A value this build does not know.
    #[serde(other)]
    Unknown,
}

/// Fields every human-channel evidence object records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestBinding {
    /// Tenant resolved from the channel.
    pub tenant: TenantId,
    /// Approval request decided.
    pub request_id: RequestId,
    /// Nonce of that request.
    pub nonce: Nonce,
    /// Approval challenge (PROTOCOL §3.3).
    pub challenge: Sha256,
    /// The decision.
    pub decision: Decision,
    /// Time the gate received the decision.
    pub received_at: UnixSecs,
    /// Level the request required, present only when it is above every configured channel and
    /// the evidence `level` is that of the strongest configured channel (PROTOCOL §6.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_level: Option<Level>,
}

/// A1 evidence: an inline-button press attested by Telegram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramButtonEvidence {
    /// Contract version, 1.
    pub v: u32,
    /// [`Channel::TelegramButton`].
    pub channel: Channel,
    /// [`Level::A1`].
    pub level: Level,
    /// Request binding.
    #[serde(flatten)]
    pub binding: RequestBinding,
    /// Consent bot id.
    pub bot_id: i64,
    /// Private chat of the prompt.
    pub chat_id: i64,
    /// Prompt message.
    pub message_id: i64,
    /// Telegram user who pressed.
    pub approver_user_id: i64,
    /// `callback_query.id`.
    pub callback_query_id: String,
    /// `update_id` of the press.
    pub update_id: i64,
}

/// Fields of a Mini App decision with verified `initData` (PROTOCOL §7.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MiniAppFields {
    /// Consent bot id.
    pub bot_id: i64,
    /// Telegram user who decided.
    pub approver_user_id: i64,
    /// Raw `initData`, re-verifiable by the third-party Ed25519 signature.
    pub init_data: String,
    /// SHA-256 of `init_data`, the replay key.
    pub init_data_sha256: Sha256,
    /// `auth_date` from `initData`.
    pub auth_date: UnixSecs,
    /// Environment whose key verified `initData`.
    pub telegram_env: TelegramEnv,
    /// Whether the owner edited the content.
    pub edited: bool,
    /// Content hash of the edited body, when edited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited_content_sha256: Option<Sha256>,
}

/// A2 evidence: a Mini App decision with verified `initData`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramMiniAppEvidence {
    /// Contract version, 1.
    pub v: u32,
    /// [`Channel::TelegramMiniApp`].
    pub channel: Channel,
    /// [`Level::A2`].
    pub level: Level,
    /// Request binding.
    #[serde(flatten)]
    pub binding: RequestBinding,
    /// The Mini App decision.
    #[serde(flatten)]
    pub miniapp: MiniAppFields,
}

/// A2+ evidence: a Mini App decision with verified `initData` after the owner's PIN or password
/// passed the gate's check (PROTOCOL §7.5). Never carries the PIN or anything derived from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramMiniAppPinEvidence {
    /// Contract version, 1.
    pub v: u32,
    /// [`Channel::TelegramMiniAppPin`].
    pub channel: Channel,
    /// [`Level::A2Plus`].
    pub level: Level,
    /// Request binding.
    #[serde(flatten)]
    pub binding: RequestBinding,
    /// The Mini App decision.
    #[serde(flatten)]
    pub miniapp: MiniAppFields,
    /// Time the gate accepted the PIN or password for this decision.
    pub pin_verified_at: UnixSecs,
}

/// A0 evidence: a release under an open mandate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenMandateEvidence {
    /// Contract version, 1.
    pub v: u32,
    /// [`Channel::OpenMandate`].
    pub channel: Channel,
    /// [`Level::A0`].
    pub level: Level,
    /// Releasing tenant.
    pub tenant: TenantId,
    /// The open mandate.
    pub open_mandate: MandateId,
    /// SHA-256 of the open mandate's compact form.
    pub open_mandate_sha256: Sha256,
    /// Message counter under that mandate, from 1.
    pub counter: u32,
    /// Evaluation time.
    pub evaluated_at: UnixSecs,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weaker_channels_never_satisfy_stronger_levels() {
        assert!(Channel::TelegramButton.satisfies(Level::A1));
        assert!(!Channel::TelegramButton.satisfies(Level::A2));
        assert!(Channel::TelegramMiniApp.satisfies(Level::A1));
        assert!(!Channel::TelegramMiniApp.satisfies(Level::A2Plus));
        assert!(Channel::TelegramMiniAppPin.satisfies(Level::A2Plus));
        assert!(!Channel::TelegramMiniAppPin.satisfies(Level::A3));
        assert!(!Channel::OpenMandate.satisfies(Level::A1));
        assert!(!Channel::Passkey.satisfies(Level::A0));
        assert!(serde_json::from_str::<Channel>("\"policy\"").is_err());
    }
}
