# ForgeCustomer — Claude Code Context

This file provides guidance to Claude Code (claude.ai/code) when working with code in this
repository.

Authority for customer identity, commerce, licensing, entitlements, installations, devices, usage,
and commercial audit for BDS products (first: AuthorForge). Rust + Axum, entry `api/src/main.rs`.

Canonical reference: `doc/FOCSYSTEM.md` (build: `bash doc/system/BUILD.sh`).
Ownership matrix: [docs/DATA_AUTHORITY.md](docs/DATA_AUTHORITY.md).
Contracts: [contracts/](contracts/) — `openapi.yaml`, `entitlement-v1.schema.json`,
`lease-v1.schema.json`, `events/`.

---

## Hard rules (violating one is a defect)

1. **Authority boundaries are sacred.** Supabase Auth owns login identity. Stripe owns payment
   processing. ForgeCustomer owns customer/commercial truth. DataForge only *receives* sanitized
   evidence and is never a source of truth here.
2. **Customer clients never receive the service-role key or Stripe secrets.** Privileged mutations
   pass through the ForgeCustomer API.
3. **Customers never directly alter commercial truth** — subscriptions, licenses, entitlements,
   usage totals, audit are service-role / RLS-protected.
4. **Usage and audit ledgers are append-only.** Corrections are compensating events, never edits
   or deletes.
5. **Fail closed** on license and entitlement mutations and on auth.
6. **Only verified webhooks activate entitlements** — never a browser redirect. Stripe webhook
   processing is idempotent and tolerates duplicate and out-of-order delivery.
7. **DataForge integration is asynchronous through the outbox.** A DataForge outage must never
   break a customer transaction.
8. **Never store creative customer content** (manuscripts, prompts) here.
9. **Preserve local product access when cloud is unavailable.** An expired subscription never
   blocks manuscript access; offline leases bridge connectivity gaps.
10. **Migrations are additive** and deterministic on rerun — one canonical system under
    `supabase/migrations/`.
11. **No `unwrap()` / `expect()` in production paths.** Use the `AppError` contract in
    `api/src/error.rs`.

Enforced by `supabase/tests/rls_customer_write_denial.sql`,
`update_eligibility_matrix.sql`, `release_pipeline_smoke.sql`, and the unprotected-table assertion
in `.github/workflows/ci.yml`.

---

## Verification

```bash
cd api && cargo fmt --all --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all
```

That is what CI runs. The SQL suites above run against a live Postgres in the same workflow.

---

## Non-obvious

- **SQLx uses the runtime query API, not compile-time macros** — the crate builds and
  `cargo test` runs with no live database.
- Docker here requires sudo; for a real database use a throwaway Postgres from
  `/usr/lib/postgresql/16/bin` on port 5433 rather than the docker path.
- Admin auth is an **HS256 JWT**, which does not match the EdDSA scheme used on the customer
  storefront side — the two ends are not interchangeable.
- Documentation ships in the same change as the implementation.
