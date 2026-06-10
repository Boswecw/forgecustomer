# ForgeCustomer

ForgeCustomer is the **customer, commerce, licensing, entitlement, installation, and
usage authority** for Boswell Digital Solutions products. The initial product served is
**AuthorForge**, but the schema and service are designed to support future products
without redesign.

## What ForgeCustomer owns

Customer identity & profiles, products & plans, Stripe customer linkage, subscriptions,
licenses, installations, devices, entitlements, usage quotas, the usage ledger,
commercial audit history, and the customer deletion workflow.

## What ForgeCustomer does *not* own

Manuscripts, creative project content, diagnostics, findings, operational repair data,
Sentinel records, or general ecosystem knowledge. See [`docs/DATA_AUTHORITY.md`](docs/DATA_AUTHORITY.md).

## Architecture

A dedicated Supabase project (Auth + PostgreSQL + RLS) fronted by a Rust/Axum API.

```
ForgeCustomer
├── Supabase Auth            login identity, sessions, refresh tokens
├── PostgreSQL               customer & commercial truth (this repo's migrations)
├── Row Level Security       customer isolation
├── ForgeCustomer API        Rust + Axum (api/)
├── Stripe integration       payment processing linkage
├── Entitlement signing      Ed25519 signed snapshots
├── Usage metering           append-only ledger + quotas
└── DataForge event outbox   sanitized downstream events
```

| Authority        | Source of truth for                                            |
| ---------------- | ------------------------------------------------------------- |
| Supabase Auth    | login identity, email verification, sessions, refresh tokens  |
| ForgeCustomer DB | customers, subscriptions, licenses, entitlements, usage, audit |
| Stripe           | payments, invoices, payment methods, raw payment events       |
| DataForge        | sanitized operational/commercial evidence (never source of truth) |

## Repository layout

```
api/         Rust + Axum service
supabase/    config, migrations, seed
contracts/   OpenAPI, entitlement schema, event schemas
tests/       integration / security / stripe / licensing / entitlement
doc/system/  canonical system source tree
doc/         generated FOCSYSTEM.md
docs/        supporting data authority, security, API, domain docs
deploy/      deployment assets
```

## Quick start

```bash
cp .env.example .env          # fill in real secrets (never commit .env)
cd api && cargo build
cargo test
cargo run                     # serves on $HOST:$PORT (default 0.0.0.0:8080)
```

Apply migrations with the Supabase CLI:

```bash
supabase db reset             # local dev: applies migrations + seed
```

## Documentation

Start with the generated canonical reference [`doc/FOCSYSTEM.md`](doc/FOCSYSTEM.md).
Edit its source parts under [`doc/system/`](doc/system/) and rebuild with
`bash doc/system/BUILD.sh`.

Supporting authority docs live in [`docs/DATA_AUTHORITY.md`](docs/DATA_AUTHORITY.md).
Security posture lives in [`docs/SECURITY.md`](docs/SECURITY.md). Per-domain docs:
[STRIPE](docs/STRIPE.md), [LICENSING](docs/LICENSING.md), [ENTITLEMENTS](docs/ENTITLEMENTS.md),
[USAGE](docs/USAGE.md), [PRIVACY](docs/PRIVACY.md), [RUNBOOK](docs/RUNBOOK.md).

## License

Proprietary — © Boswell Digital Solutions.
