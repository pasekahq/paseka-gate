//! PIN rules of the A2+ channel (PROTOCOL §7.5): the PIN kind setting, its default by
//! deployment and the online attempt limit. The verifier and its pepper belong to the gate;
//! nothing here holds or derives a secret.

use paseka_proto::{TenantId, UnixSecs};

use crate::tenant::TenantMap;

/// Consecutive wrong attempts that freeze PIN entry.
pub const PIN_MAX_FAILURES: u32 = 5;
/// How long PIN entry stays frozen, counted from the failure that froze it: 15 min.
pub const PIN_FREEZE_SECS: u64 = 15 * 60;
/// Length of a PIN of kind [`PinKind::SixDigits`].
pub const PIN_DIGITS: usize = 6;
/// Minimum length in Unicode scalar values of a secret of kind [`PinKind::Password`].
pub const PASSWORD_MIN_CHARS: usize = 12;

/// Who runs the gate that holds a tenant's PIN verifier and pepper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deployment {
    /// The tenant's owner runs the gate.
    SelfHost,
    /// A hosting operator runs the gate for the tenant.
    Hosted,
}

/// What the owner's A2+ secret is: a security setting that holds no secret itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinKind {
    /// Exactly [`PIN_DIGITS`] ASCII digits.
    SixDigits,
    /// At least [`PASSWORD_MIN_CHARS`] characters, none of them a control character.
    Password,
}

/// A candidate secret that does not fit its [`PinKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadPin {
    /// Not exactly [`PIN_DIGITS`] ASCII digits.
    NotSixDigits,
    /// Fewer than [`PASSWORD_MIN_CHARS`] characters.
    TooShort,
    /// Contains a control character, such as a newline read along with the password.
    ControlCharacter,
}

impl PinKind {
    /// The kind a tenant starts with: a password when hosted, six digits on self-host.
    #[must_use]
    pub const fn default_for(deployment: Deployment) -> Self {
        match deployment {
            Deployment::SelfHost => Self::SixDigits,
            Deployment::Hosted => Self::Password,
        }
    }

    /// Checks a new PIN or password against this kind before the gate stores its verifier.
    ///
    /// # Errors
    /// [`BadPin`] naming the first rule `candidate` breaks.
    pub fn check(self, candidate: &str) -> Result<(), BadPin> {
        match self {
            Self::SixDigits => {
                if candidate.len() == PIN_DIGITS && candidate.bytes().all(|b| b.is_ascii_digit()) {
                    Ok(())
                } else {
                    Err(BadPin::NotSixDigits)
                }
            }
            Self::Password => {
                if candidate.chars().any(char::is_control) {
                    Err(BadPin::ControlCharacter)
                } else if candidate.chars().count() < PASSWORD_MIN_CHARS {
                    Err(BadPin::TooShort)
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// The result of one PIN entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    /// The PIN matched; the failure count is back to zero.
    Accepted,
    /// The PIN did not match; `remaining` more failures freeze entry.
    Wrong {
        /// Failures left before the freeze.
        remaining: u32,
    },
    /// This failure froze entry until `until`. The caller notifies the owner, once per freeze.
    FreezeStarted {
        /// End of the freeze.
        until: UnixSecs,
    },
    /// Entry is frozen until `until`; the PIN was not checked and the freeze is unchanged.
    Frozen {
        /// End of the freeze.
        until: UnixSecs,
    },
}

#[derive(Debug, Clone, Copy, Default)]
struct Attempts {
    failures: u32,
    frozen_until: Option<UnixSecs>,
}

/// Per-tenant count of consecutive wrong PIN entries and the resulting freeze.
#[derive(Debug, Clone, Default)]
pub struct PinLimiter {
    tenants: TenantMap<(), Attempts>,
}

impl PinLimiter {
    /// One PIN entry by `tenant` at `now`. `check` runs the verifier and is called only when
    /// entry is not frozen.
    pub fn attempt(
        &mut self,
        tenant: &TenantId,
        now: UnixSecs,
        check: impl FnOnce() -> bool,
    ) -> PinOutcome {
        let state = self.tenants.entry(tenant, ());
        match state.frozen_until {
            Some(until) if now < until => return PinOutcome::Frozen { until },
            Some(_) => *state = Attempts::default(),
            None => {}
        }
        if check() {
            *state = Attempts::default();
            return PinOutcome::Accepted;
        }
        state.failures += 1;
        if state.failures < PIN_MAX_FAILURES {
            return PinOutcome::Wrong {
                remaining: PIN_MAX_FAILURES - state.failures,
            };
        }
        let until = now.saturating_add(PIN_FREEZE_SECS);
        state.frozen_until = Some(until);
        PinOutcome::FreezeStarted { until }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::tenant;

    #[test]
    fn pin_kinds_accept_only_fitting_secrets() {
        let cases: [(PinKind, &str, Result<(), BadPin>); 11] = [
            (PinKind::SixDigits, "123456", Ok(())),
            (PinKind::SixDigits, "000000", Ok(())),
            (PinKind::SixDigits, "12345", Err(BadPin::NotSixDigits)),
            (PinKind::SixDigits, "1234567", Err(BadPin::NotSixDigits)),
            (PinKind::SixDigits, "12345a", Err(BadPin::NotSixDigits)),
            (PinKind::SixDigits, "١٢٣٤٥٦", Err(BadPin::NotSixDigits)),
            (PinKind::Password, "correct horse", Ok(())),
            (PinKind::Password, "пароль-пароль", Ok(())),
            (PinKind::Password, "short pass1", Err(BadPin::TooShort)),
            (
                PinKind::Password,
                "correct horse\n",
                Err(BadPin::ControlCharacter),
            ),
            (PinKind::Password, "", Err(BadPin::TooShort)),
        ];
        for (kind, candidate, want) in cases {
            assert_eq!(kind.check(candidate), want, "{kind:?} {candidate:?}");
        }
    }

    #[test]
    fn hosted_tenants_default_to_a_password() {
        assert_eq!(PinKind::default_for(Deployment::Hosted), PinKind::Password);
        assert_eq!(
            PinKind::default_for(Deployment::SelfHost),
            PinKind::SixDigits
        );
    }

    /// One step of a limiter script: time, whether the PIN is right, expected outcome, and
    /// whether the verifier must have run.
    type Step = (UnixSecs, bool, PinOutcome, bool);

    fn run(steps: &[Step]) {
        let mut limiter = PinLimiter::default();
        for (i, &(now, right, want, checked)) in steps.iter().enumerate() {
            let mut ran = false;
            let got = limiter.attempt(&tenant(1), now, || {
                ran = true;
                right
            });
            assert_eq!((got, ran), (want, checked), "step {i} at {now}");
        }
    }

    const FREEZE_AT: UnixSecs = 104;
    const THAW: UnixSecs = FREEZE_AT + PIN_FREEZE_SECS;

    fn five_failures() -> Vec<Step> {
        let mut steps: Vec<Step> = (0..4)
            .map(|i| {
                (
                    100 + i,
                    false,
                    PinOutcome::Wrong {
                        remaining: PIN_MAX_FAILURES - 1 - u32::try_from(i).unwrap(),
                    },
                    true,
                )
            })
            .collect();
        steps.push((
            FREEZE_AT,
            false,
            PinOutcome::FreezeStarted { until: THAW },
            true,
        ));
        steps
    }

    #[test]
    fn the_fifth_consecutive_failure_freezes_entry_once() {
        let mut steps = five_failures();
        steps.extend([
            (FREEZE_AT, false, PinOutcome::Frozen { until: THAW }, false),
            (THAW - 1, true, PinOutcome::Frozen { until: THAW }, false),
            (THAW - 1, false, PinOutcome::Frozen { until: THAW }, false),
        ]);
        run(&steps);
    }

    #[test]
    fn the_freeze_ends_at_its_time_with_a_fresh_count() {
        let mut steps = five_failures();
        steps.extend([
            (THAW - 1, false, PinOutcome::Frozen { until: THAW }, false),
            (
                THAW,
                false,
                PinOutcome::Wrong {
                    remaining: PIN_MAX_FAILURES - 1,
                },
                true,
            ),
            (THAW + 1, true, PinOutcome::Accepted, true),
        ]);
        run(&steps);
    }

    #[test]
    fn a_right_pin_resets_the_count() {
        let mut steps = five_failures();
        steps.truncate(4);
        steps.extend([
            (110, true, PinOutcome::Accepted, true),
            (
                111,
                false,
                PinOutcome::Wrong {
                    remaining: PIN_MAX_FAILURES - 1,
                },
                true,
            ),
            (112, true, PinOutcome::Accepted, true),
        ]);
        run(&steps);
    }

    #[test]
    fn one_tenants_freeze_leaves_another_unaffected() {
        let mut limiter = PinLimiter::default();
        for now in 100..100 + u64::from(PIN_MAX_FAILURES) {
            limiter.attempt(&tenant(1), now, || false);
        }
        assert!(matches!(
            limiter.attempt(&tenant(1), 200, || true),
            PinOutcome::Frozen { .. }
        ));
        assert_eq!(
            limiter.attempt(&tenant(2), 200, || true),
            PinOutcome::Accepted
        );
        assert_eq!(
            limiter.attempt(&tenant(2), 201, || false),
            PinOutcome::Wrong {
                remaining: PIN_MAX_FAILURES - 1
            }
        );
    }
}
