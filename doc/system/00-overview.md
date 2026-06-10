## 1. Overview

ForgeCustomer is the customer, commerce, licensing, entitlement, installation, device,
usage, privacy, and commercial-audit authority for Boswell Digital Solutions products.
The first product is AuthorForge, but the catalog and entitlement model are product
generic.

ForgeCustomer is implemented as a Rust/Axum API backed by a dedicated Supabase
PostgreSQL project. Supabase Auth supplies login identity. ForgeCustomer keeps its own
business `customer_id` and owns customer/commercial truth. Stripe owns payment
processing. DataForge receives sanitized downstream evidence and is not a source of
truth.

### Current readiness

The repository is an MVP foundation, not a complete production commerce surface.

Implemented today:

- Rust workspace with `forgecustomer-api`.
- Environment-driven configuration with fail-closed token verification.
- Axum router, liveness/readiness/version endpoints, correlation IDs, and security
  headers.
- API-owned account provisioning that maps a Supabase auth subject to one ForgeCustomer
  business customer profile idempotently.
- Stripe webhook signature verification, minimal non-PII event parsing, and idempotent
  webhook receipt/dedupe.
- Public product and plan catalog endpoints backed by SQLx repositories.
- Customer and admin JWT extraction boundaries.
- Public entitlement key endpoint and Ed25519 signing/key-ring services.
- Pure domain logic for subscription normalization, entitlement precedence, usage
  decisions, device limits, offline lease validation, redaction, Stripe webhook signature
  verification, and DataForge publish hygiene.
- Supabase migrations for identity, catalog, commerce, licensing, entitlements, usage,
  audit/outbox, privacy, RLS, and seed constraints.
- CI for Rust formatting, clippy, tests, migration determinism, RLS coverage, OpenAPI
  linting, schema parsing, secret scan, and dependency audit.

Still pending before AuthorForge can rely on the service end to end:

- DB-backed checkout/session creation and subscription state application from received
  Stripe webhook events.
- Installation registration, activation, heartbeat, deactivation, and revocation routes.
- Entitlement snapshot assembly from plan/grants/overrides and offline-lease issuance.
- Usage reserve/commit/release/current endpoint wiring.
- Admin handler implementations.
- Outbox emit sites and deletion workflow endpoints.

The router intentionally returns `NOT_IMPLEMENTED` for many protected handlers while
still enforcing the correct auth boundary. That is a security feature of the current
stage: unimplemented endpoints must not return partial commercial truth.

### Repository map

```text
api/                    Rust + Axum service crate
api/src/config.rs       Environment configuration
api/src/error.rs        Stable JSON error contract
api/src/state.rs        Shared app state, SQLx pool, signing, validators, HTTP client
api/src/auth/           JWT validation, customer/admin extractors
api/src/middleware/     Correlation ID and security headers
api/src/domain/         Pure business rules
api/src/routes/         HTTP routes
api/src/repositories/   SQLx repository functions
api/src/integrations/   Stripe and DataForge integration helpers
api/src/services/       Signing and service-level helpers
api/src/workers/        DataForge outbox worker
contracts/              OpenAPI, entitlement schema, outbox event schema
supabase/migrations/    Ordered SQL migrations
supabase/seed.sql       Deterministic seed data
docs/                   Supporting domain docs and runbooks
doc/system/             Canonical system source tree
doc/FOCSYSTEM.md        Generated canonical system artifact
```

### Primary doctrine

- Customer clients never receive Supabase service-role keys, Stripe secrets, admin
  secrets, or entitlement signing private keys.
- All privileged commercial mutations go through the ForgeCustomer API.
- Browser redirects never activate entitlements. Verified Stripe webhooks do.
- Usage and commercial audit data are append-only. Corrections are compensating events.
- DataForge outage must not block customer transactions; the outbox queues sanitized
  evidence for retry.
- ForgeCustomer never stores manuscripts, prompts, creative project content, diagnostics,
  Sentinel records, repair findings, or general ecosystem knowledge.
