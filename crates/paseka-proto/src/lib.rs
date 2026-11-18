//! Wire and data types of paseka-gate.
//!
//! Readers are tolerant: unknown fields are ignored and optional fields default. Required fields
//! and security-relevant enums (mandate kind, approval level, signature algorithm) stay strict: a
//! missing or unknown value is a parse error, never a permissive default.

#![forbid(unsafe_code)]

pub mod draft;
pub mod envelope;
pub mod evidence;
pub mod ids;
pub mod jws;
pub mod level;
pub mod mandate;
pub mod tools;

pub use ids::{DocId, DraftId, GateId, Nonce, PeerId, Sha256, TenantId};
pub use level::Level;

/// Unix time in seconds. The core never reads a clock; callers pass `now`.
pub type UnixSecs = u64;
