//! Approval channel selection (PROTOCOL §6.2, §6.3): which configured channel approves a
//! required level. A level above every configured channel is approved through the strongest
//! one and marked, never blocked; the required level itself is never lowered.

use paseka_proto::Level;
use paseka_proto::evidence::Channel;

/// The human approval channels a tenant has configured: at least one, never the open mandate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channels(Vec<Channel>);

/// A channel list with no human channel, or with the open mandate in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadChannels;

/// Which configured channel an approval request goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// The weakest configured channel that satisfies the required level.
    Satisfies(Channel),
    /// No configured channel satisfies the required level; this is the strongest configured one.
    AboveAvailable(Channel),
}

impl Channels {
    /// The configured channels.
    ///
    /// # Errors
    /// [`BadChannels`] when `configured` is empty or names [`Channel::OpenMandate`].
    pub fn new(configured: Vec<Channel>) -> Result<Self, BadChannels> {
        if configured.is_empty() || configured.contains(&Channel::OpenMandate) {
            return Err(BadChannels);
        }
        Ok(Self(configured))
    }

    /// The channel for `required`; among equally strong channels the first configured wins.
    ///
    /// # Panics
    /// Never: [`Channels::new`] refuses an empty list.
    pub fn select(&self, required: Level) -> Selection {
        let weakest_satisfying = self
            .0
            .iter()
            .copied()
            .filter(|c| c.strength() >= required)
            .reduce(|best, c| {
                if c.strength() < best.strength() {
                    c
                } else {
                    best
                }
            });
        if let Some(c) = weakest_satisfying {
            return Selection::Satisfies(c);
        }
        let strongest = self
            .0
            .iter()
            .copied()
            .reduce(|best, c| {
                if c.strength() > best.strength() {
                    c
                } else {
                    best
                }
            })
            .expect("Channels is never empty");
        Selection::AboveAvailable(strongest)
    }
}

impl Selection {
    /// The selected channel.
    pub fn channel(self) -> Channel {
        match self {
            Self::Satisfies(c) | Self::AboveAvailable(c) => c,
        }
    }

    /// The level a deciding channel must satisfy for a request that required `required`:
    /// `required` itself, or the strongest configured channel's level when `required` is above it.
    pub fn floor(self, required: Level) -> Level {
        match self {
            Self::Satisfies(_) => required,
            Self::AboveAvailable(c) => c.strength(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Channel::{Passkey, TelegramButton, TelegramMiniApp, TelegramMiniAppPin};

    #[test]
    fn selects_the_weakest_satisfying_or_the_strongest_marked() {
        let mvp = [TelegramButton, TelegramMiniApp, TelegramMiniAppPin];
        let cases: [(&[Channel], Level, Selection); 7] = [
            (&mvp, Level::A1, Selection::Satisfies(TelegramButton)),
            (&mvp, Level::A2, Selection::Satisfies(TelegramMiniApp)),
            (
                &mvp,
                Level::A2Plus,
                Selection::Satisfies(TelegramMiniAppPin),
            ),
            (
                &mvp,
                Level::A3,
                Selection::AboveAvailable(TelegramMiniAppPin),
            ),
            (
                &[TelegramMiniAppPin],
                Level::A3,
                Selection::AboveAvailable(TelegramMiniAppPin),
            ),
            (
                &[TelegramMiniAppPin, TelegramButton, Passkey],
                Level::A2Plus,
                Selection::Satisfies(TelegramMiniAppPin),
            ),
            (
                &[TelegramButton, TelegramMiniApp],
                Level::A2Plus,
                Selection::AboveAvailable(TelegramMiniApp),
            ),
        ];
        for (configured, required, want) in cases {
            let channels = Channels::new(configured.to_vec()).unwrap();
            assert_eq!(
                channels.select(required),
                want,
                "{configured:?} at {required}"
            );
        }
    }

    #[test]
    fn a_weaker_channel_never_reaches_a_level_a_configured_channel_satisfies() {
        let mvp = Channels::new(vec![TelegramButton, TelegramMiniApp, TelegramMiniAppPin]).unwrap();
        for (required, weaker) in [
            (Level::A2, TelegramButton),
            (Level::A2Plus, TelegramMiniApp),
            (Level::A2Plus, TelegramButton),
        ] {
            let floor = mvp.select(required).floor(required);
            assert_eq!(floor, required);
            assert!(!weaker.satisfies(floor), "{weaker:?} at {required}");
        }
        let above = mvp.select(Level::A3);
        assert_eq!(above.floor(Level::A3), Level::A2Plus);
        assert!(TelegramMiniAppPin.satisfies(above.floor(Level::A3)));
        assert!(!TelegramMiniApp.satisfies(above.floor(Level::A3)));
    }

    #[test]
    fn the_channel_list_is_human_and_not_empty() {
        assert_eq!(Channels::new(vec![]), Err(BadChannels));
        assert_eq!(
            Channels::new(vec![TelegramButton, Channel::OpenMandate]),
            Err(BadChannels)
        );
    }
}
