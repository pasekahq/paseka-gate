//! Pure consent logic of paseka-gate.
//!
//! No I/O, no clock, no randomness: callers pass `now` and gate-issued nonces in. Every check
//! here can only refuse or raise friction; nothing in this crate can approve on the owner's
//! behalf. The tenant key signs mandates and envelopes only after a decision passed
//! [`draft::Draft::decide`] or an open mandate matched; the agent interface never reaches it.

#![forbid(unsafe_code)]

pub mod channel;
pub mod draft;
pub mod envelope;
pub mod hash;
pub mod mandate;
pub mod open;
pub mod pairing;
pub mod peer;
pub mod pin;
pub mod risk;
pub mod shelf;
pub mod template;
pub mod tenant;
pub mod token;
pub mod tripwire;

#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod vectors;
