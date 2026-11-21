# Contributing to paseka-gate

Thanks for helping. The organization-wide guide is
[pasekahq/.github CONTRIBUTING](https://github.com/pasekahq/.github/blob/main/CONTRIBUTING.md);
this file adds what is specific to `paseka-gate`. Coding agents (and humans) also follow
[AGENTS.md](AGENTS.md): layout, commands, contracts, budgets.

## Before you start
- Read [docs/concept/CONCEPT.md](docs/concept/CONCEPT.md) (owner decisions, binding),
  [docs/PROTOCOL.md](docs/PROTOCOL.md) and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
- Bugs and feature ideas: open an issue first. Protocol, contract or security-property changes
  need an ADR in `docs/adr/` (template in `docs/adr/README.md`) before or with the code.
  `contracts/` only grow.
- Security issues: never in public issues, see [SECURITY.md](SECURITY.md).

## Checks
```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 ci/broad_check.py
cargo deny check advisories bans licenses sources
```
CI also runs gitleaks over the full history, MSRV, the static musl build with size and dependency
budgets, the conformance attacks and a reproducible-build check. `main` is protected: every change
lands through a pull request with green CI.

## Sign-off (DCO), no CLA
Every commit must be signed off under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):

```
Signed-off-by: Your Name <you@example.com>
```

Use `git commit -s` (or `git rebase --signoff main` for commits you already made). The sign-off
must match the commit author. The `dco` check enforces it on pull requests from outside the
maintainer team.

## License
`paseka-gate` is licensed under [AGPL-3.0-only](LICENSE). By signing off you certify that you have
the right to submit your contribution under that license, and you license it under the same terms.
