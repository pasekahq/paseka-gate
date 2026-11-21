# Draft review

State of the first draft after integration of the spec, skeleton and product pieces. Binding
input: `docs/concept/CONCEPT.md`. Source of truth for shapes and behaviour: `docs/PROTOCOL.md`
and `contracts/`.

## Solid

- Protocol. `docs/PROTOCOL.md` fixes ids, digests, the draft state machine, the agent tools and
  errors, risk stages, approval checks, mandates, the gate-to-gate wire, pairing and tenancy.
  `contracts/` has a schema for every boundary object with valid and invalid fixtures and
  byte-exact vectors.
- Types match contracts. `paseka-proto` deserialises every valid fixture and rejects every
  invalid one; the few rules that bind writers only are listed with their enforcing check in
  `crates/paseka-proto/tests/contracts.rs`. Authority-bearing values (`v`, `alg`, `typ`, kind,
  level, trust, channel, envelope type, decision) fail to parse when unknown.
- Byte-exact interop. `paseka-core` reproduces the release digests, the approval challenge, the
  short authentication string, the signed closed mandate and the signed envelope of
  `contracts/fixtures/vectors/digests.json`.
- Core logic. Draft states and the approval-request checks of PROTOCOL §7.1
  (`draft::Draft::decide`), receiver verification of envelopes and mandates (§10.3, §8.4), open
  mandate shape, matching, counters and the one-pending rule (§8.3, §9.1), shelf shares and the
  note rule (§9.3), typed template fields (§9.2), monotonic risk evaluation with the S12
  no-flag rule.
- Threat model to tests. Every SP-1 to SP-22 has at least one CA; every CA-1 to CA-52 has a test
  `caNN_*` in `crates/paseka-conformance/tests/attacks.rs`. 38 run and pass; 14 are ignored
  with the missing part named. Every MVP DoD item names its checks.
- Tooling. `python3 ci/broad_check.py` is green (fmt, clippy `-D warnings`, tests). `deny.toml`
  bans the async and heavy crates. Budget and reproducible-build scripts exist.
- Decisions. ADRs 0001 to 0012 agree with PROTOCOL and the concept; README and AGENTS describe
  the current layout and rules.

## Thin

- No gate daemon yet: no storage, MCP server, HTTP API, consent bot, Mini App, pairing, journal,
  outbox or retry. Pending attacks: CA-4, 5, 11, 14, 16, 17, 23, 35, 37, 38, 42 to 46. DoD items
  d7, d8, d14, d16 to d22 have no passing check.
- Mini App `initData` verification (Ed25519 third-party signature, HMAC, freshness, replay) is
  specified but not implemented.
- Risk: no phone, address or national-id detectors (S5); no per-peer topic policy (S6), MCP
  source log (S9) or fuzzy stage (S10); canaries in attachment text are not scanned yet, so
  CA-19 covers only the body. Fingerprints are exact shingle sets, not MinHash.
- Volume and rate limits (agent drafts per hour, pending drafts, inbound peer volume, spike
  suspension) are specified but not in core.
- Body and attachment byte limits and the U+0000 rule are not enforced in `paseka-proto`; the gate
  must check them on input.
- `cargo deny`, gitleaks, `ci/budgets.sh` and `ci/repro-build.sh` were not run locally
  (cargo-deny is not installed on this host).
- `skills/install/SKILL.md` uses CLI surfaces that do not exist yet: `paseka conformance
  --target ... --tenant ...`, `paseka status`, `paseka init --tenant alice --bot-token-stdin`,
  `deploy/systemd/paseka.service`. Tenant ids are opaque `t_` ULIDs, so `--tenant alice` needs a
  local name mapping.

## Decisions taken by agents (owner to confirm)

1. The gate signs every closed mandate with the tenant key on the owner's behalf; the evidence
   stays in the journal behind `evidence_sha256` (ADR 0012). AP2 has the user sign.
   Closed: GRILL 1 confirms it; ADR 0012 stands, owner attestation comes after the MVP.
2. One Ed25519 key per tenant signs mandates, envelopes, receipts and pairing messages,
   separated by the JWS `typ`. The key id is the tenant's address.
   Closed: GRILL 2, 2a and D1 changed it: the address is the permanent tenant id, keys rotate with a commitment or owner-confirmed change; ADR 0013, PR #4, #5, #6.
3. The release digest binds tenant, both key ids, thread, reply target, content hash and
   attachment metadata, not only the content hash.
   Closed: GRILL 3 changed it: both addresses instead of key ids, plus the draft `expires`; ADR 0014, PR #7.
4. Agent tool inputs reject unknown fields (`invalid_input`); all other readers are tolerant.
   Closed: GRILL 4 confirms it; ADR 0010.
5. Templates and shelf shares need A1 unless a matching open mandate covers them. The concept
   line "auto-release only for structured/template output or under an open mandate" is read
   with "T0: nothing without consent" as: templates auto-release only under a T1 mandate.
   Closed: GRILL 5 confirms it (ADR 0006); still open: the one-tap T1 offer at pairing is not in PROTOCOL yet.
6. A receiving gate rejects a closed mandate whose `exp - iat` exceeds 60 s.
   Closed: GRILL 6 confirms 60 s and the re-issue on retry while the draft lives (ADR 0014, PR #7); still open: a receiver's per-peer loosening, PROTOCOL §14 keeps it fixed.
7. With the MVP channels, drafts that need A2+ or A3 (fingerprint or sensitive-source hits) are
   blocked with reason `policy`; the owner may lower that floor to A2 through consent.
   Closed: GRILL 7 and 7a changed it: never blocked for a missing channel, the strongest available channel decides, A2+ is Mini App plus PIN; ADR 0015, PR #8, #9.
8. A canary hit puts the tenant into tripwire mode: open mandates stop and every draft needs A2
   until the owner clears it.
   Closed: GRILL 8 changed it: tripwire needs A2+ and clears only with the PIN, full alarm by default; ADR 0016, PR #11.
9. A `conversation` trust (one thread, short window, message count) exists beside T1 to T3.
   Closed: GRILL 9, 11 and D3 changed it: one thread, 30 min, no message limit, inside the source registry; ADR 0017, ADR 0019, PR #12, #13, #15.
10. Pairing: invite deep link, pair URI handed to the invitee's own gate, both owners consent at
    A2, optional six-digit short authentication string.
    Closed: GRILL 10 confirms it and adds the not-verified mark capping the peer at T1; ADR 0020, PR #16.
11. Defaults: prompt TTL 3600 s, `initData` window 300 s, closed mandate 60 s, envelope window
    7 days, retry horizon 72 h, 30 drafts per peer per hour, 20 pending drafts per tenant.
    Closed: GRILL 11 changed them: draft lifetime 12 h, 50 pending drafts, conversation 30 min without message limit; ADR 0017, PR #12.
12. Peer turns run as a separate agent invocation with its own launch profile (ADR 0011).
    Closed: GRILL 12 changed it: a recommendation with levels L1 to L3 and the L1 marker, not protocol; ADR 0011, PR #18.
13. Conformance attacks are numbered from CA-1 and only appended; CA-47 (A1 approval of an
    A2 request) was added to cover "a weaker channel never satisfies a stronger level".
    Closed: GRILL 13 confirms it; CA-48 to CA-57 were appended (PR #5 to #17).

## Open questions

1. Is it acceptable that a receiving gate trusts the sending gate's claim of A1/A2 consent?
   Recommended: yes for the MVP; peers see level and channel as the sender's claim, and A2+/A3
   bring owner-key signatures that peers verify.
   Closed: GRILL O1 and D4: yes for the MVP, stated in THREAT-MODEL A-5 and §7, owner attestation after the MVP; PR #23.
2. Where does the install skill live? The concept says the steps live in the skill, not in the
   repo; ADR 0008 says the skill is shipped and pinned separately, yet its source is in
   `skills/install/`. Recommended: keep the source here for review, publish it as a separately
   signed release artifact, and have the owner hand the installing agent a pinned copy.
   Closed: GRILL O2: source here, a separately signed release, its hash in three places, a self-check first; ADR 0008, PR #19.
3. Hosted mode: one shared consent bot for all tenants or one bot per tenant? Recommended: one
   bot per tenant for self-host; one shared bot on the hosted gate, tenant resolved from the
   request (PROTOCOL TI-5, CA-39).
   Closed: GRILL O3: own bot for self-host, a shared bot on the hosted gate resolving the tenant from the signed Telegram user id, an own bot optional; ADR 0022, PR #20.
4. Telegram's Ed25519 public keys are pinned from the Bot API documentation. Recommended: verify
   the production and test keys against the current documentation and add Telegram's own
   example `initData` as a test vector before M3.
   Closed: GRILL O4: keys and the documented vector in the config, a live check at the ceremony (M3), changes through consent or the local CLI; ADR 0022, PR #20.
5. Should fingerprint hits be blocked or held at A2 in the MVP? Recommended: blocked (current
   rule), since A2+ does not exist yet and a silent downgrade is what ADR 0005 forbids.
   Closed: GRILL 7 (O5): held, not blocked; the strongest available channel decides; ADR 0015, PR #8, #9.
6. Is a 1 h default prompt TTL right? Recommended: keep 1 h as default, owner setting 5 min to
   24 h; open mandates cover the fast cases.
   Closed: GRILL 11 (O6): the draft lifetime is 12 h, 5 min to 7 days; the prompt TTL stays 1 h; ADR 0017, PR #12.
7. Should templates without a T1 mandate really need A1 (decision 5)? Recommended: yes; it keeps
   T0 strict and costs one tap.
   Closed: GRILL 5 (O7): yes, and the owner may change it; ADR 0006.
8. CLI naming of tenants for self-host. Recommended: `paseka init` creates a local tenant name
   (`alice`) mapped to the opaque `t_` id; the id never appears in the CLI.
   Closed: GRILL O8: local names mapped to addresses, never seen by peers; PROTOCOL §12.1, PR #21, the CLI in M2.
9. Fingerprints: exact shingles or MinHash for the MVP? Recommended: exact shingles now (cheap,
   exact); MinHash when sensitive folders exceed a few thousand documents.
   Closed: GRILL O9: exact shingles in the MVP, MinHash later, inside the source registry; ADR 0018, ADR 0021, PR #14, #17.
10. CONCEPT.md names the old gate repository by its real owner path. Recommended: keep it in the
    owner's concept only; no other file names it.
    Closed: GRILL O10: a link in the concept's History section, named nowhere else; PR #22.

## Next 5 steps

1. Storage and the release transaction: rusqlite schema with `(tenant, id)` keys, "consume
   nonce, issue mandate, commit outbox envelope, move to released" in one transaction, the
   hash-chained journal. Unlocks CA-45, CA-46.
2. Agent server: `paseka mcp` (stdio relay) and loopback HTTP over `tools::ToolCall`, error
   mapping, agent rate and pending limits, tenant from the agent token. Unlocks CA-5, CA-38,
   CA-43 and d4.
3. Consent: consent bot (A1) and Mini App (A2) with the HMAC step of `initData` and the server
   around `initdata::InitData::verify`; first-run ceremony. Unlocks CA-4, CA-11, CA-14, CA-16, CA-17, CA-23 and
   d7, d8, d16.
4. Peers: pairing messages and invite codes, outbox with retry, inbound endpoint around
   `envelope::Receiver`, peer volume limits, a two-gate loopback test. Unlocks CA-35, CA-37,
   CA-44 and d14.
5. Release hygiene: install cargo-deny and gitleaks on the build host, run `ci/budgets.sh` and
   `ci/repro-build.sh`, align `skills/install/SKILL.md` with the real CLI.
