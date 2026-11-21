//! Freshness of Telegram Mini App `initData` (PROTOCOL §7.4 step 5).

use std::ops::RangeInclusive;

use paseka_proto::UnixSecs;

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
    use super::*;

    const NOW: UnixSecs = 1_794_268_830;

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
