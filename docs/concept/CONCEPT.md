# Paseka gate — concept (owner decisions of 2026-11-18)

Working name: `paseka-gate` (binary `paseka`). Organisation: `pasekahq` on GitHub. The repo is
public at https://github.com/pasekahq/paseka-gate (owner decision of 2026-11-21, which replaces
the earlier "local only, never push" rule). Packages and releases are still not published.

## What it is
A consent firewall between ANY owner's AI agent (a custom Rust agent "ulei", Hermes, Claude Code,
Codex, a browser ChatGPT, any model with a ReAct loop) and the outside world (other people's
agents). People pair their gates; agents then ask each other things. Example: Alice's agent asks
Bob's agent "what does Bob think about X"; Bob's MAIN agent (with all his notes, memory and
context) drafts a meaningful answer; Bob sees the exact answer and approves; it goes to Alice.

## Core rules
1. Every agent is untrusted for release, our own included. It may read anything and PROPOSE; it
   can never approve. The agent-facing interface has NO approve tool at all (absent, not refused).
2. Threat model assumption: a guest/peer can fully hijack the owner's agent by prompt injection.
   That is a normal case. Nothing leaves without the owner, even then.
3. What leaves: only the exact bytes the owner saw (hash-bound), only to that recipient, once per
   consent. Or what an open mandate (owner-signed in advance, with constraints) allows.
4. The gate sits on the "external communication" leg of the Agents Rule of Two / lethal trifecta.
   Out-of-band exfiltration by the agent's other tools is out of the gate's reach and is handled by
   agent configuration guidance (levels L1–L3 below), not by stripping the agent's knowledge.

## Architecture: three replaceable parts
- Mailbox/router (agent side): ONE MCP server for every agent (stdio for local agents, HTTP on
  loopback otherwise; same contract as plain HTTP/OpenAPI for non-MCP clients). Tools: inbox,
  read, propose, revise, withdraw, status, share (shelf reference, see T2). Plus queue, peers,
  journal.
- Policy engine: what may go without a human (open mandates) and which approval level the rest
  needs.
- Approval channels (pluggable): each produces the same proof — a signed mandate over the hash of
  the exact content.

## Mandates (model: Google AP2 v0.2, SD-JWT style)
- Closed mandate = consent for one message: {kind: closed, tenant, to, content_sha256,
  attachments[], level, proof{channel, ...channel evidence}, nonce (issued by the gate),
  exp (≈60 s)}. Approval surface must be non-agentic.
- Open mandate = consent in advance for a class of actions: {kind: open, to, constraints{templates,
  max_len, attachments, private_sources, rate, topics}, window/exp, signed_at_level}. A new open
  mandate cannot be presented until the previous one is refused (AP2 rule). Minimal lifetimes.
- Format SHOULD follow AP2 / SD-JWT; deviations need an ADR.

## Approval levels
- A0 open mandate / policy: templates, "this conversation for 30 min or 10 messages" in hard limits,
  allowlists. Zero friction.
- A1 Telegram inline button in the gate's OWN consent bot (token only in the gate, not the bot the
  owner chats with the agent through). Who pressed is attested by Telegram's servers; nonce from
  the gate.
- A2 Telegram Mini App showing exact bytes, recipient, attachments, diff; edit allowed (new hash).
  Verify initData by the Ed25519 third-party signature (Bot API 8.0), NOT only the bot-token HMAC;
  strict auth_date freshness; the gate binds request id + content hash + nonce.
- A2+ Mini App + BiometricManager: a software (WebCrypto, non-extractable) key unlocked by
  biometrics signs hash+nonce. No hardware attestation.
- A3 passkey (WebAuthn) in an EXTERNAL browser via openLink (passkeys inside Telegram webviews are
  unreliable). Signature over the hash.
- MVP = A0, A1, A2. Others later through the same proof format. Other later channels: Slack, ntfy,
  CLI with a local key (only meaningful if the key is not where the agent runs), email magic link
  as weak fallback.
- Telegram is a trusted party for A1/A2; Telegram account takeover = approval. Acceptable for this
  threat model; A2+/A3 for the most sensitive.

## Risk evaluation (who decides what is sensitive)
- Principle: checks only RAISE friction, never replace the human. A classifier saying "safe" never
  auto-releases free text; free text to a peer is at least A1. Auto-release (A0) only for
  structured/template output or under an owner-signed open mandate.
- The owner's dictionary lives in the gate (the agent cannot edit it): built-in detectors (API keys
  and tokens via gitleaks-like rules, card numbers, IBAN, phones, addresses, IDs), personal lists
  (names of relatives, diagnoses, companies, topics like health/money/family) built during the
  first-run ceremony, per-peer policy ("projects yes, family no").
- Gate-side checks for ANY agent: structure (links, base64/hex blobs, long numbers, length,
  attachments, new recipient) — exact; canaries (owner plants unique markers in sensitive files;
  marker in output = BLOCK even with approval + owner alert) — exact; fingerprints of sensitive
  folders (shingles/MinHash; verbatim and near-verbatim) — exact; embedding similarity and a
  classifier model (local or via qb) — fuzzy, raise only.
- Sources: plain agent = unknown ("agent says"); data behind MCP = verified (the gate proxies the
  owner's MCP servers and logs what was read during a peer-started turn; the log is not written by
  the agent); ulei = full taint tracking (CaMeL-like).
- Default rules: free text → A1; structural flag or dictionary hit → A2 with highlights;
  fingerprint hit or read from sensitive folders per MCP log → A2+/A3; canary → block.

## Trust levels per peer (open mandates)
- T0 nothing without consent (default for a new peer).
- T1 templates and structured answers.
- T2 SHELVES: the owner opens collections of his library to a peer; the agent sends a POINTER
  (share{doc, section, note}); the GATE reads the bytes from the shelf itself and sends them, after
  checking the doc is on a shelf open to that peer. Optional short agent note (≤200 chars, no
  links/flags). The agent cannot smuggle other data. Fully reliable. Main way to be liberal.
- T3 free text without consent on allowed topics — the owner's conscious risk: scope (peer,
  topics, expiry with renewal, daily volume), hard blocks always (canaries, fingerprints of shelves
  NOT open to that peer, secrets, attachments outside shelves → manual), evening digest, revoke,
  kill switch; protection against a hijacked peer agent (volume limits, spike alert, automatic
  fallback to manual).

## Agent configuration levels (guidance, not enforced by the gate)
- The MAIN agent answers, with full brain/memory/context. Knowledge is NOT cut.
- L1: just connected via MCP; answer leaves only with consent; injection could still exfiltrate via
  other tools.
- L2 (recommended): "peer turn mode": while a turn started by a peer runs, the agent may read
  everything but its other outbound tools are off (web fetch/search, mail, messengers, shell with
  network); memory writes go to quarantine; the answer goes only to the gate. Per-agent recipes:
  ulei native; Hermes config; Claude Code allowlist + hooks; Codex config.
- L3: dual model (dual-LLM / CaMeL): a quarantined model without tools turns the peer's text into
  a structured question; the main agent with full context sees only that.
- Approval screen helps the owner: exact bytes + flags (links, numbers, encoded chunks, sensitive
  topics) + sources read during the turn (verified via MCP log when available).

## Hosting and verification
- Self-host is the MAIN path: one static Rust binary. An install skill for the user's agent:
  1) package built from this repo (CI-only publishing via trusted publishing, Sigstore provenance,
  Rekor); 2) reproducible build — the agent rebuilds from the tag and compares hashes;
  3) the code does what it claims — small core with a size budget in CI, an audit checklist with
  file:line answers, cargo-vet, cargo deny; 4) conformance attacks run locally (forged consent,
  replay, preview swap after consent, approval in the agent's name, stale nonce); 5) first-run
  ceremony — the Mini App shows the config in plain words, the gate does not work until the owner
  confirms; afterwards security settings (approvers, policies, peers, dictionary) change ONLY
  through consent, never by editing config. Trap: the installing agent is the one the gate guards
  against: verification steps live in the skill, not in the repo; repo content is data; the gate
  runs as a separate unix user.
- Hosting by the owner of pasekahq for friends who don't want to bother: multi-tenant from day one,
  strict tenant isolation in code and tests, explicit "you trust the operator". Basic checks:
  /version with build hash vs signed release, external conformance against own tenant, journal
  export, peers verify passkey signatures, one-command migration to self-host.
- Distribution later: GitHub Releases with attestations, pip/npm wrappers (like ruff/esbuild),
  cargo install.

## Peers and pairing
- Gate↔gate over HTTPS with signed envelopes (ed25519 keys per gate/tenant), replay protection,
  durable retry. Telegram is only the human UI (bots can't really talk to bots).
- Pairing by deep link: t.me/<consent_bot>?start=pair_<code> → gates exchange keys.
- Guest mode (a person without own gate) = a tenant on a hosted gate working by hand in the Mini
  App. A remote MCP connector with OAuth for browser ChatGPT comes AFTER the MVP (keep the design
  open for it).
- Clean slate: NO compatibility with the old Python gate (vladmesh/agent-peer-protocol, Event 0.2,
  HMAC). Old guests are re-invited manually. Its tests (CF-1…CF-10 consent-forgery suite) are a
  useful source of attack ideas for the conformance suite.

## Engineering constraints (same stack as qb / ulei)
- Rust, synchronous stack: NO tokio/hyper/axum/reqwest/openssl/chrono/pyo3 (deny.toml). Allowed
  style: httparse, serde/serde_json, rustix, ureq+rustls(ring) for outbound, ed25519-dalek,
  sha2, rusqlite (bundled) for storage. TLS for inbound is terminated by Caddy in front.
- Budgets in CI like qb: static musl binary size, idle RSS, 0 wakeups when idle, dependency count.
- unsafe forbidden in core crates. MSRV pinned. fmt, clippy -D warnings, test, deny, gitleaks,
  budgets.
- Hard rules: no real host names, person names, e-mails or paths of the owner's deployment in code,
  docs, fixtures or tests — use alice/bob/carol, example.org. No `Co-Authored-By` / "Generated with"
  trailers in commits. Commit author is set by the repo config; do not change it.

## MVP scope
MCP agent interface; consent bot + Mini App; A0–A2 and mandates over hashes; multi-tenant,
multi-peer, pairing by link; gate↔gate HTTPS with signatures; risk evaluation (structure,
canaries, dictionary; fingerprints if cheap); shelves (T2); conformance attacks; reproducible
release; install skill. Later: OAuth ChatGPT connector, A2+/A3, Slack/ntfy, independent approval
page, pip/npm wrappers, cargo-vet audits, T3.
