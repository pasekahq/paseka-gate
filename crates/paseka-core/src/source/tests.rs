use paseka_proto::evidence::Channel;

use super::*;
use crate::testkit::{BOB_INBOUND, CHAT, address, audiences, settle, tenant};

const OTP: Source = Source::BuiltIn(BuiltIn::OneTimeCodes);
const SECRETS: Source = Source::BuiltIn(BuiltIn::Secrets);

fn change<'a>(
    tenant: &'a TenantId,
    source: Source,
    peer: &'a Address,
    access: Access,
    surface: Surface,
    channel: Channel,
) -> Change<'a> {
    Change {
        tenant,
        source,
        peer,
        access,
        surface,
        channel,
    }
}

#[test]
fn every_source_is_ask_until_decided_and_one_time_codes_are_never() {
    let mut reg = SourceRegistry::default();
    reg.register(&tenant(1), SourceId(1), SourceKind::Files)
        .unwrap();
    let d = reg.towards(&tenant(1), &address(2));
    assert_eq!(d.access(SECRETS), Access::Ask);
    assert_eq!(d.access(Source::Registered(SourceId(1))), Access::Ask);
    assert_eq!(d.access(OTP), Access::Never);
    assert_eq!(Decisions::new().access(OTP), Access::Never);
}

#[test]
fn one_time_codes_stay_never_whatever_the_surface_or_channel() {
    let (t, bob) = (tenant(1), address(2));
    let mut reg = SourceRegistry::default();
    for access in [Access::Allow, Access::Ask] {
        for surface in [Surface::Settings, Surface::Prompt] {
            let c = change(&t, OTP, &bob, access, surface, Channel::TelegramMiniAppPin);
            assert_eq!(reg.change(&c), Err(ChangeError::Fixed));
        }
    }
    assert_eq!(reg.towards(&t, &bob).access(OTP), Access::Never);
}

#[test]
fn never_is_set_and_lifted_only_on_the_settings_page() {
    let (t, bob) = (tenant(1), address(2));
    let mut reg = SourceRegistry::default();
    let pin = Channel::TelegramMiniAppPin;
    let set_never = change(&t, SECRETS, &bob, Access::Never, Surface::Prompt, pin);
    assert_eq!(
        reg.change(&set_never),
        Err(ChangeError::NeverOnlyInSettings)
    );
    settle(&mut reg, SECRETS, &bob, Access::Never);
    for access in [Access::Allow, Access::Ask] {
        let lift = change(&t, SECRETS, &bob, access, Surface::Prompt, pin);
        assert_eq!(reg.change(&lift), Err(ChangeError::NeverOnlyInSettings));
    }
    assert_eq!(reg.towards(&t, &bob).access(SECRETS), Access::Never);
    let lift = change(&t, SECRETS, &bob, Access::Allow, Surface::Settings, pin);
    assert_eq!(reg.change(&lift), Ok(()));
    assert_eq!(reg.towards(&t, &bob).access(SECRETS), Access::Allow);
}

#[test]
fn ask_and_allow_change_through_a_prompt_at_a2_only() {
    let (t, bob) = (tenant(1), address(2));
    let mut reg = SourceRegistry::default();
    for channel in [Channel::OpenMandate, Channel::TelegramButton] {
        let c = change(&t, SECRETS, &bob, Access::Allow, Surface::Prompt, channel);
        assert_eq!(reg.change(&c), Err(ChangeError::ChannelTooWeak));
        let c = Change {
            surface: Surface::Settings,
            ..c
        };
        assert_eq!(reg.change(&c), Err(ChangeError::ChannelTooWeak));
    }
    assert_eq!(reg.towards(&t, &bob).access(SECRETS), Access::Ask);
    let allow = change(
        &t,
        SECRETS,
        &bob,
        Access::Allow,
        Surface::Prompt,
        Channel::TelegramMiniApp,
    );
    assert_eq!(reg.change(&allow), Ok(()));
    assert_eq!(reg.towards(&t, &bob).access(SECRETS), Access::Allow);
    let ask = Change {
        access: Access::Ask,
        ..allow
    };
    assert_eq!(reg.change(&ask), Ok(()));
    assert_eq!(reg.towards(&t, &bob).access(SECRETS), Access::Ask);
}

#[test]
fn a_source_is_registered_once_and_only_in_its_own_tenant() {
    let (t1, t2, bob) = (tenant(1), tenant(2), address(2));
    let mut reg = SourceRegistry::default();
    reg.register(&t1, SourceId(1), SourceKind::AgentContext)
        .unwrap();
    assert_eq!(
        reg.register(&t1, SourceId(1), SourceKind::Files),
        Err(ChangeError::AlreadyRegistered)
    );
    assert_eq!(reg.kind(&t1, SourceId(1)), Some(&SourceKind::AgentContext));
    assert_eq!(reg.kind(&t2, SourceId(1)), None);
    let other_tenant = change(
        &t2,
        Source::Registered(SourceId(1)),
        &bob,
        Access::Allow,
        Surface::Settings,
        Channel::TelegramMiniApp,
    );
    assert_eq!(reg.change(&other_tenant), Err(ChangeError::UnknownSource));
}

#[test]
fn a_chat_is_allow_towards_its_members_and_own_messages_towards_their_sender() {
    let reg = audiences();
    let (chat, inbound) = (Source::Registered(CHAT), Source::Registered(BOB_INBOUND));
    let cases = [
        (2, Access::Allow, Access::Allow),
        (3, Access::Allow, Access::Ask),
        (4, Access::Ask, Access::Ask),
    ];
    for (peer, chat_access, inbound_access) in cases {
        let d = reg.towards(&tenant(1), &address(peer));
        assert_eq!(d.access(chat), chat_access, "peer {peer}");
        assert_eq!(d.access(inbound), inbound_access, "peer {peer}");
    }
    assert_eq!(
        reg.towards(&tenant(2), &address(2)).access(chat),
        Access::Ask
    );
}

#[test]
fn owner_decisions_override_the_audience_defaults_and_never_stays_in_settings() {
    let (t, bob, dave) = (tenant(1), address(2), address(4));
    let mut reg = audiences();
    let (chat, inbound) = (Source::Registered(CHAT), Source::Registered(BOB_INBOUND));
    let pin = Channel::TelegramMiniAppPin;
    let to_never = change(&t, chat, &bob, Access::Never, Surface::Prompt, pin);
    assert_eq!(reg.change(&to_never), Err(ChangeError::NeverOnlyInSettings));
    let ask = change(&t, inbound, &bob, Access::Ask, Surface::Prompt, pin);
    assert_eq!(reg.change(&ask), Ok(()));
    settle(&mut reg, chat, &bob, Access::Never);
    settle(&mut reg, chat, &dave, Access::Allow);
    assert_eq!(reg.towards(&t, &bob).access(chat), Access::Never);
    assert_eq!(reg.towards(&t, &bob).access(inbound), Access::Ask);
    assert_eq!(reg.towards(&t, &address(3)).access(chat), Access::Allow);
    assert_eq!(reg.towards(&t, &dave).access(chat), Access::Allow);
    assert_eq!(reg.towards(&t, &bob).access(OTP), Access::Never);
}
