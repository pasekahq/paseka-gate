//! Pure consent logic of paseka-gate.
//!
//! No I/O, no clock, no randomness: callers pass `now` and gate-issued nonces in. Every check
//! here can only refuse or raise friction; nothing in this crate can approve on the owner's
//! behalf. Signing exists only for approval channels and tests, never for the agent interface.

#![forbid(unsafe_code)]

pub mod draft;
pub mod envelope;
pub mod hash;
pub mod mandate;
pub mod nonce;
pub mod risk;
pub mod shelf;
pub mod tenant;
pub mod token;
pub mod trust;

#[cfg(test)]
pub(crate) mod testkit;
