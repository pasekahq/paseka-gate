# Security policy

paseka-gate is a consent firewall: its whole point is that nothing leaves without the owner's
consent. Please report anything that breaks that privately.

## Reporting a vulnerability
**Do not report vulnerabilities in public issues, discussions or pull requests.**

Use GitHub private vulnerability reporting:
[Report a vulnerability](https://github.com/pasekahq/paseka-gate/security/advisories/new)
(Security tab → Report a vulnerability). Include the affected commit, impact, reproduction steps
or a proof of concept, and any suggested fix.

Response times, disclosure window and credit follow the
[pasekahq security policy](https://github.com/pasekahq/.github/blob/main/SECURITY.md):
acknowledgement within 3 business days, up to 90 days before public disclosure.

## Supported versions
Pre-alpha, no releases yet. Only `main` receives fixes.

## Especially interesting
- An agent causing a release without owner consent (approve paths, mandate forgery or replay,
  digest mismatches between what the owner saw and what was sent).
- Breaking tenant isolation, the consent channel (bot, Mini App, initData) or the PIN step.
- Envelope signature, pairing or key-rotation bypasses between gates.
- The conformance attacks in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) that pass when they
  should not.

Out of scope: third-party services, attacks that need root on the host, social engineering,
volume DoS.
