# 0007. Multi-tenant from day one

Status: Accepted
Date: 2026-11-18

## Context
Friends who do not want to run a server will use a gate hosted by the pasekahq operator. Guests
without any gate are tenants too. Retrofitting tenancy into storage, keys and routing later is
costly and error-prone.

## Decision
- Every stored row, key, mandate, envelope and log line carries a tenant id.
- Tenant isolation is a type-level invariant in `paseka-core` (an operation takes a tenant
  context and cannot address another tenant's data) and is checked by conformance tests.
- Each tenant has its own Ed25519 identity key, consent bot binding, dictionary, peers and
  journal.
- A self-hosted gate is a deployment with one tenant; the code path is the same.

## Consequences
- Cross-tenant reads and releases are named conformance attacks.
- The hosted operator can still read tenant data; hosted tenants are told so explicitly
  (ADR 0008).
- Migration from a hosted tenant to self-host is one export and one import of the tenant.
