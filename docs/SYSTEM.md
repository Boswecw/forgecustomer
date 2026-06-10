# SYSTEM.md — ForgeCustomer system overview

> Canonical generated system reference now lives at `doc/FOCSYSTEM.md`. Edit
> `doc/system/*.md` and run `bash doc/system/BUILD.sh` for canonical updates.

## Mission

ForgeCustomer is the single authority for customer identity, commerce, licensing,
entitlement, installation, and usage for Boswell Digital Solutions (BDS) products. The
first product is **AuthorForge**. The schema is product-generic so future products are
added as data, not as schema redesigns.

## Components

```
                   ┌────────────────────────┐
   Customer  ──────│  AuthorForge desktop   │
   (browser) ──────│  BDS website           │───┐  signed JWT (Supabase Auth)
                   └────────────────────────┘   │
                                                 ▼
   ┌─────────────┐   verify JWT   ┌──────────────────────────────┐
   │ Supabase    │◀──────────────│      ForgeCustomer API        │
   │ Auth        │               │  (Rust + Axum, this repo/api) │
   └─────────────┘               │  - middleware (JWT, ctx, rate) │
                                 │  - services (commerce, license,│
   ┌─────────────┐   Checkout    │    entitlement, usage)         │
   │   Stripe    │◀──────────────│  - repositories (SQLx)         │
   │             │──webhook─────▶│  - Ed25519 entitlement signing │
   └─────────────┘               │  - outbox worker               │
                                 └───────────────┬───────────────┘
   ┌─────────────┐   sanitized                   │ SQLx
   │  DataForge  │◀── outbox ────────────────┐    ▼
   │             │   (async worker)          │  ┌───────────────────┐
   └─────────────┘                           └──│ ForgeCustomer DB  │
                                                │ (Postgres + RLS)  │
   ┌─────────────┐   admin API                  └───────────────────┘
   │Forge Command│◀─────────────────────────────────▲
   │ (operators) │── operator JWT ───────────────────┘
   └─────────────┘
```

## Request lifecycle (customer)

1. Client authenticates with Supabase Auth and receives a short-lived JWT.
2. Client calls the ForgeCustomer API with the JWT.
3. Middleware assigns a correlation ID, validates the JWT (issuer/audience/exp),
   resolves the **customer context** (maps `auth_user_id` → ForgeCustomer customer), and
   enforces status (suspended customers are blocked from privileged actions).
4. The route handler invokes a service; services use repositories; privileged mutations
   write an audit event and (where relevant) an outbox event in the same transaction.
5. Responses follow the error contract on failure (`docs/API.md`).

## Subsystems

- **Identity** (`0001`, Phase 2): customer profiles, status history, emails, consent.
- **Catalog** (`0002`, Phase 3): products, plans, versioned features and quotas.
- **Commerce** (`0003`, Phase 5): billing accounts, Stripe linkage, subscriptions,
  checkout sessions, webhook events.
- **Licensing** (`0004`, Phase 6): licenses, installations, devices, activations, leases,
  revocations.
- **Entitlements** (`0005`, Phase 7): grants, overrides, signed snapshots.
- **Usage** (`0006`, Phase 8): meters, append-only events, reservations, period totals,
  quota decisions.
- **Audit & outbox** (`0007`, Phases 9 & 11): commercial audit log, DataForge outbox.
- **Privacy** (`0008`, Phase 12): policy versions, consent, deletion requests.
- **RLS** (`0009`, Phase 18): customer isolation policies.
- **Constraints/seed guards** (`0010`).

## Environments

Separate Supabase projects and secret sets for **development**, **staging**, and
**production**. Start in development. Never share secrets across environments.

## Service stack

Rust, Axum, SQLx (runtime API), Tokio, Serde, Tower / tower-http, Tracing, Reqwest,
Supabase JWT validation (`jsonwebtoken`), Stripe via HTTP, Ed25519 via `ed25519-dalek`.
