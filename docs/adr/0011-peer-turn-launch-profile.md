# 0011. Peer-turn protection levels are a recommendation the gate records and shows

Status: Recommendation
Date: 2026-11-21

## Context
A hijacking peer message can make the agent that reads it leak through the agent's other
outbound tools (web fetch, mail, messengers, a shell with network), outside the gate. How that
agent is set up is outside the gate's reach: the gate sees only calls on the agent interface. It
cannot tell which tools the agent had, under which unix user it ran, or whether a separate run
handled the peer turn, and nothing the agent reports about itself is evidence. A level the gate
enforced would be a claim it cannot check.

The owner of the agent that reads incoming peer messages carries this risk. The gate's own
guarantees (consent for exact bytes, no approve tool, canaries, the source registry) hold at every
level.

`docs/concept/CONCEPT.md` names an older scale: connected as the lowest level, "peer turn mode"
(outbound tools off during a peer turn, by config, hooks or native support) as the middle one,
and a dual-model technique (a quarantined model turns the peer text into a structured question)
as the highest. This ADR deviates from it: the owner replaced that scale with the one below, OS
restrictions are the highest level, the dual-model technique is not a level, and the levels are
a recommendation rather than part of the protocol.

## Decision
- Protection levels are guidance for configuring the agent that reads incoming peer messages, not
  protocol. The gate does not verify them.
- L3: OS restrictions. The agent runs as a separate unix user whose network reaches only the
  model API and the gate. Works for any agent.
- L2: a separate run through `paseka peer-turn`. Fits any CLI agent. Where the agent can, the run
  starts from a fork of the owner's main session, so it has the full context; otherwise it starts
  fresh from the owner's notes. The run has only read tools and the paseka server, and writes
  memory only to a quarantine directory the owner reviews. Until the runner ships (after the MVP,
  `docs/MVP.md`), the owner's scheduler starts the same run with the command in the agent's
  recipe.
- L1: the owner accepts the risk knowingly.
- Hooks that block tools for the rest of a session after a peer message (session taint) are
  defense in depth only. Alone they leave the agent at L1; at L2 or L3 they add a layer.
- The connect skill asks the owner for the level. The owner records it in the Mini App when
  registering the agent, as a security setting (`docs/PROTOCOL.md` §5.4, §9.4); the agent cannot
  set or change it.
- The gate shows the recorded level to the owner on every approval prompt and in the Mini App peer
  and agent views, labelled as the owner's statement. For L1 it keeps the permanent marker
  "Incoming messages from peers are read without protection."
- The dual-model technique is an after-MVP recipe, not a level.

## Consequences
- `docs/AGENT-SETUP.md` and the recipes in `skills/connect/recipes/` describe each level per
  agent; L3 has one recipe for every agent (`skills/connect/recipes/os-restrictions.md`).
- A wrong recorded level misleads only the owner who recorded it; it changes no approval level and
  no release decision (ADR 0005).
- An owner who runs an agent at L1 sees the marker on every prompt for that agent's drafts until
  the owner records another level or removes the agent.
