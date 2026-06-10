# CLAUDE.md — ForgeCustomer engineering doctrine

This file orients any agent (or human) working in this repository. Read it before
making changes. It encodes non-negotiable rules; violating them is a defect.

## What this system is

ForgeCustomer is the authority for **customer identity, commerce, licensing,
entitlements, installations, devices, usage, and commercial audit** for Boswell Digital
Solutions products (first: AuthorForge). See `doc/FOCSYSTEM.md` for the generated
canonical system reference and `docs/DATA_AUTHORITY.md` for the ownership matrix.

## Hard rules (fail the change if violated)

1. **Authority boundaries are sacred.** Supabase Auth owns login identity. Stripe owns
   payment processing. ForgeCustomer owns customer/commercial truth. DataForge only
   *receives* sanitized evidence and is never a source of truth.
2. **Customer clients never receive the service-role key or Stripe secrets.** Secrets
   stay server-side. All privileged mutations pass through the ForgeCustomer API.
3. **Customers never directly alter commercial truth** (subscriptions, licenses,
   entitlements, usage totals, audit). Those are service-role / RLS-protected.
4. **Usage and audit ledgers are append-only.** Corrections are compensating events,
   never edits or deletes.
5. **Fail closed** for license and entitlement mutations and for auth.
6. **Stripe webhook processing is idempotent** and tolerant of out-of-order/duplicate
   events. Browser redirects never activate entitlements — only verified webhooks do.
7. **DataForge integration is asynchronous through the outbox.** A DataForge outage must
   never break a customer transaction.
8. **Never store creative customer content** (manuscripts, prompts) here.
9. **Preserve local product access when cloud is unavailable.** Expired subscriptions
   never block manuscript access; offline leases bridge connectivity gaps.
10. **Migrations are additive** and deterministic on rerun. One canonical migration
    system under `supabase/migrations`.
11. **Strict Rust error handling.** No `unwrap()`/`expect()` in production paths; use the
    `AppError` contract in `api/src/error.rs`.
12. **Update documentation in the same change as implementation.**

## Layout

- `api/` — Rust + Axum service. Entry `api/src/main.rs`.
  - `config.rs` env config, `error.rs` error contract, `state.rs` shared state.
  - `auth/` JWT validation & context, `middleware/` tower layers,
    `domain/` types & pure logic, `services/` business logic,
    `repositories/` DB access, `integrations/` Stripe/DataForge, `routes/` HTTP,
    `workers/` background (outbox publisher).
- `supabase/migrations/` — ordered SQL (`0001_..` → `0010_..`).
- `contracts/` — `openapi.yaml`, `entitlement-v1.schema.json`, `events/`.
- `tests/` — integration / security / stripe / licensing / entitlement.
- `doc/system/` — canonical system source tree; build `doc/FOCSYSTEM.md` with
  `bash doc/system/BUILD.sh`.
- `docs/` — supporting design, authority, API, domain, and runbook docs.

## Build & test

```bash
cd api
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

SQLx is used via the **runtime query API** (no compile-time macros), so the crate
builds without a live database.

## Phase model

Work phase by phase (see the implementation plan). Documentation precedes broad
implementation. Add tests with every feature.
