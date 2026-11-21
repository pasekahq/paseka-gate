# 0013. A tenant's address is its permanent id; keys rotate under it

Status: Accepted
Date: 2026-11-21

## Context
Peers need a name for a tenant that survives a key change, a key compromise and a move to
another gate. A key id cannot be that name: rotating the key would change the address and break
every pairing, and a stolen key would be the identity itself. The owner decided (GRILL items 2,
2a, 3, addition D1) that the address is the tenant's permanent id, that keys rotate by a message
signed with the old key and auto-accepted by peers, and that a path must exist which does not
depend on the old key alone.

## Decision

### Address
- The address of a tenant towards peers is its tenant id `t_` + ULID. It is assigned once, at
  tenant creation, and never changes, also across export and migration to self-host.
- Addresses are global. Uniqueness rests on the 80 random bits of the ULID from the OS CSPRNG;
  no registry exists.
- An address is a name, not a credential. It is bound to a key only by the pairing exchange and
  the key messages below. A gate refuses a pairing whose peer address is one of its own tenants or
  is already recorded for another peer of the same tenant.
- Every wire field that names a tenant is an address: envelope and receipt `iss`/`aud`, pairing
  `iss`/`aud`, mandate `iss`/`to`. Mandates keep `tenant`, which equals `iss`; a receiver refuses
  a mandate where they differ. The release digest binds `tenant`, `iss` and `to` as addresses.
- In code the address is its own type (`paseka_proto::Address`) with no conversion to or from a
  key id.

### Key
- A key is named only by JWS `kid` and by explicit key fields (`key` in pairing messages, `k` in
  the pair URI, the key messages below). No field holds a key id in place of an address.
- Each tenant has one current Ed25519 key; JWS `typ` separates the signing domains.
- A verifier looks up the peer by `iss` address, then requires `kid` to name a key valid for that
  peer now; a mismatch is `bad_signature`.

### Peer record
Per tenant and peer address the gate stores: the endpoint, the current key, the commitment
`next_key_sha256` to the peer's next key (absent until the peer sends one), the previous key with
`previous_valid_until`, and the pairing state. A key is valid for the peer when it is the current
key, or the previous key while `now < previous_valid_until`.

### Routine rotation
- The owner starts a rotation through consent with PIN or password (GRILL 7a). The gate creates
  the new key and sends every active peer a `key.rotate` envelope: `{new_key,
  next_key_sha256, previous_valid_until}`, signed with the old key, plus a proof of possession,
  a signature by the new key over the same payload.
- `next_key_sha256` is SHA-256 of the 32-byte public key that will follow `new_key`
  (pre-rotation). The gate generates that following key pair at the same time and stores its
  private key apart from the current key: sealed with a key derived from the owner's PIN or
  password and the pepper of GRILL D2, opened only inside the consent that starts the next
  rotation. Pairing messages carry the first commitment.
- The receiver auto-accepts a rotation, without asking its owner, when all hold: the envelope
  verifies with the current key of that address; the proof verifies with `new_key`; and
  SHA-256 of `new_key` equals the `next_key_sha256` on record. It then moves the current key to
  previous, sets `previous_valid_until`, makes `new_key` current and stores the new commitment.
- `previous_valid_until` is `iat + N`. The sender sets N; the receiver caps it at 30 days.
- Default N is 7 days, an owner setting from 1 to 30 days, changed only through consent like
  every security setting (PROTOCOL §9.4). Reason: 7 days equals the envelope acceptance window
  (PROTOCOL §10.3), so every envelope still acceptable by its age, retries of up to 72 h
  included, was signed by a key that is still valid, and a peer gate that was offline for up to a
  week still learns the new key before the old one stops.

### Change without a usable commitment
When the commitment is absent, lost, or itself suspected (the sealed next key may have leaked
with the current one), the owner changes the key through consent with PIN, and the gate sends
`key.rotate` without the commitment match. The receiver does not auto-accept it: the peer stays
on its current key, and the receiver's owner gets a key-change notice and confirms in the Mini
App at A2 after comparing, out of band, a short authentication string over both addresses, the
old key and the new key. The sending owner tells the peer through a separate channel. Until that
confirmation the old key keeps working and the new one is not accepted.

### Compromise and revocation
- `key.revoke` declares the current key compromised. Signed with the compromised key alone it
  only removes authority: the receiver stops accepting that key at once (no grace) and marks the
  peer `key_revoked`, so a thief can use the message for denial of service, which holding the
  key already allows, and never to install a key.
- A revocation that installs a replacement meets the same requirement as a rotation: signed by
  the pre-committed next key (the receiver checks it against `next_key_sha256`), or confirmed by
  the receiving owner as in the path without a commitment. The revoked key gets no grace; the
  sender re-seals undelivered envelopes with the new key.

### Contract versioning
The address change is made in place in contract version 1: `iss`/`aud`/`to` change type and
pairing messages gain the required `key` field. Version 1 has no release, no tag and no deployed
peer, so no producer depends on the old shape, and a `/v2/` prefix would leave a version 1 that
nothing ever implemented. `contracts/README.md` records the change. Every later change of
version 1 follows the only-grow rule of ADR 0010.

## Consequences
- Pairings survive key rotation, compromise recovery and migration; only the endpoint changes on
  migration.
- The receiver's tables (`seen` event ids, accepted `jti`s, open-mandate slots) key on addresses,
  so a rotation does not reset replay protection.
- The tenant id is no longer gate-local: peers see it as the address. It already travelled in
  mandates as `tenant`.
