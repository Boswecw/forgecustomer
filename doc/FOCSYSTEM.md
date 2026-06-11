# FOCSYSTEM.md - ForgeCustomer Canonical System Reference

**Document version:** 1.0 (bootstrap)
**Document date:** 2026-06-10
**Protocol:** Forge Documentation Protocol v1
**Documentation structure class:** `system`

This `doc/system/` tree is the canonical authored source for the ForgeCustomer system
reference. The assembled artifact is generated and should not be edited directly.

Assembly contract:

- Command: `bash doc/system/BUILD.sh`
- Validation: `bash doc/system/validate_snapshots.sh doc/FOCSYSTEM.md`
- Primary output: `doc/FOCSYSTEM.md`
- Generated artifact rule: edit `doc/system/*.md`, then rebuild.

Supporting reference material remains in `docs/`, `contracts/`, `supabase/migrations/`,
and the Rust API crate. When those sources disagree, the live implementation and this
generated canonical reference must be reconciled in the same change.

| Part | File | Contents |
| --- | --- | --- |
| 1 | `00-overview.md` | Mission, current readiness, and repository ownership. |
| 2 | `01-authority-boundaries.md` | Data authority, source-of-truth rules, and out-of-scope data. |
| 3 | `02-architecture-runtime.md` | Runtime components, request lifecycle, and process behavior. |
| 4 | `03-api-contract.md` | HTTP routes, auth boundaries, errors, and correlation behavior. |
| 5 | `04-data-model.md` | Supabase/Postgres schema domains and RLS posture. |
| 6 | `05-domain-subsystems.md` | Commerce, licensing, entitlement, usage, privacy, and admin semantics. |
| 7 | `06-integrations-events.md` | Stripe, DataForge outbox, contracts, and event hygiene. |
| 8 | `07-security-privacy.md` | Token validation, secret handling, signing, PII, and fail-closed rules. |
| 9 | `08-configuration-operations.md` | Environment variables, deployment, migrations, and runbook notes. |
| 10 | `09-verification-status.md` | Tests, CI gates, runnable proof, and known MVP gaps. |
| 11 | `90-governance-change-control.md` | Change-control rules for keeping the system document current. |

## Quick Assembly

```bash
bash doc/system/BUILD.sh
```

---

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
- Axum router, liveness/readiness/version endpoints, correlation IDs, security headers,
  and router-level request guards (per-client rate limiting, body cap, timeout).
- API-owned account provisioning that maps a Supabase auth subject to one ForgeCustomer
  business customer profile idempotently.
- Stripe Checkout Session creation for active paid catalog plans.
- Stripe webhook signature verification, minimal non-PII event parsing, idempotent
  processing, subscription projection, invoice reference recording, commercial audit, and
  sanitized `subscription_changed` outbox emission.
- Subscription-linked license issuance and sync (issue/suspend/expire/reactivate, device
  limit from plan features) inside webhook processing.
- Installation registration (idempotent by install key, optional Ed25519 device
  identity), license activation with device-limit and revocation enforcement, heartbeat,
  deactivation, and read-own installation/device/license listings, with audit and
  sanitized `installation_registered` / `license_activated` outbox emission.
- Entitlement snapshot assembly from included-plan baseline, subscription plan, license
  grants, promotional grants, and admin overrides — evaluated fail-closed, Ed25519
  signed, stored for audit/replay, and returned with wire field order matching the
  canonical signing order.
- Advisory feature/quota checks and signed offline-lease issuance (`forge.lease.v1`)
  for activated installations, denied for suspended/revoked contexts.
- The Forge Command admin surface: customer lookup, suspend/restore, Stripe subscription
  resync, operator license issue/revoke, entitlement overrides, compensating usage
  adjustments, and audit reads — mutations role-gated (`admin`), reason-required, and
  audited with the operator as actor.
- The usage lifecycle: advisory checks, idempotent lock-serialized reservations with
  expiry (lazy + background sweeper), reservation/direct commits on the append-only
  ledger with explainable quota decisions, releases, and per-meter current totals;
  threshold and commit-failure outbox events.
- The account-deletion workflow: customer request/cancel, operator
  advance/reject/execute with a non-destructive cooling-off, a one-transaction
  anonymization (profile PII, emails, devices, licenses, installations) with a PII-free
  receipt and the sanitized `customer_anonymized` outbox event; anonymized accounts fail
  closed at the auth boundary. The customer subscription summary endpoint.
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

Every customer, webhook, and admin route is implemented; no handler returns
`NOT_IMPLEMENTED`. Still pending before AuthorForge can rely on the service end to end:

- CI-runnable DB-backed end-to-end suites (the live local verification suites covering
  licensing, entitlements, usage, admin, and deletion are the blueprint).

### Repository map

```text
api/                    Rust + Axum service crate
api/src/config.rs       Environment configuration
api/src/error.rs        Stable JSON error contract
api/src/state.rs        Shared app state, SQLx pool, signing, validators, HTTP client
api/src/auth/           JWT validation, customer/admin extractors
api/src/middleware/     Correlation ID, security headers, per-client rate limiting
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

---

## 2. Authority Boundaries

ForgeCustomer exists to remove data-ownership ambiguity. Each authority has a narrow
role, and the API must preserve those boundaries even when integrations fail.

### Sources of truth

| Authority | Owns | Does not own |
| --- | --- | --- |
| Supabase Auth | Login identity, email verification, sessions, refresh tokens, provider identities. | Business customer status, subscriptions, licenses, usage, entitlements. |
| ForgeCustomer PostgreSQL | Customer profiles, commercial status, subscriptions projection, licenses, installations, devices, entitlements, quotas, usage ledger, audit, deletion workflow. | Raw payment processing, card data, manuscripts, prompts, operational repair findings. |
| Stripe | Payment processing, invoices, payment methods, raw payment events. | Product entitlement truth, device activation, local content access. |
| DataForge | Sanitized downstream evidence from the outbox. | Customer identity, licensing, subscriptions, billing truth, creative content. |
| AuthorForge and product clients | Local creative work and local product state. | Commercial authority, entitlement minting, usage-ledger mutation. |
| Forge Command/operator tooling | Operator workflows through admin APIs. | Bypassing ForgeCustomer mutation paths. |

ForgeCustomer PostgreSQL is the customer and commercial source of truth.

### Boundary rules

- `auth.users.id` is an identity subject, not the business customer identifier.
  ForgeCustomer maps it to its own `customer_profiles.id`.
- Customer JWTs are valid only for customer routes. Admin routes use a separate issuer,
  audience, and secret.
- Customer clients may read their own commercial state but may not directly write
  subscriptions, Stripe mappings, licenses, entitlement grants, usage totals, audit
  records, or outbox events.
- Stripe webhooks normalize payment state into ForgeCustomer tables. Stripe remains the
  payment processor, but ForgeCustomer owns product-facing subscription projection.
- DataForge is a sink. It receives pseudonymous sanitized events; it must never be used
  to reconstruct or override commercial truth.
- Local creative data never crosses into ForgeCustomer. Product access doctrine must
  preserve local work when cloud or billing systems are unavailable.

### Explicitly out of scope

ForgeCustomer must not introduce tables, APIs, logs, outbox payloads, or documents that
store or imply ownership over:

- Manuscripts or creative project content.
- Prompt content or model-output text.
- Diagnostics, findings, repair data, Sentinel records, or ecosystem knowledge.
- Raw card data, payment methods, passwords, refresh tokens, or Supabase service-role
  keys.

### Conflict resolution

If implementation pressure creates overlap, resolve it by moving the data to the owning
system rather than expanding ForgeCustomer. A new table or endpoint is acceptable only
when it preserves the authority matrix above and has a corresponding migration,
contract/doc update, and test.

---

## 3. Architecture and Runtime

ForgeCustomer is a single Rust API process with a lazily connected PostgreSQL pool and
optional background outbox publisher.

```text
Customer/Product Client
        |
        | Supabase JWT
        v
ForgeCustomer API (Rust + Axum)
        |-- public routes: health, ready, version, catalog, entitlement keys
        |-- customer routes: customer JWT -> CustomerContext -> repositories/services
        |-- admin routes: operator JWT -> AdminContext -> repositories/services
        |-- Stripe webhook route: signature verification -> normalized state
        |
        | SQLx
        v
Supabase PostgreSQL + RLS
        |
        | transactional outbox rows
        v
Outbox worker -> DataForge sanitized events
```

### Process startup

`api/src/main.rs` is intentionally thin:

1. Initialize JSON tracing with `RUST_LOG` or the default filter
   `info,forgecustomer_api=debug`.
2. Load `Config::from_env()`.
3. Build `AppState`.
4. Spawn the DataForge outbox worker only when `DATAFORGE_API_URL` is configured.
5. Build the Axum router and serve on `HOST:PORT`.

`AppState::build` creates:

- Ed25519 signer from `ENTITLEMENT_SIGNING_PRIVATE_KEY`.
- Published key ring containing the active signing key.
- Customer JWT validator from Supabase issuer/audience/secret.
- Admin JWT validator from admin issuer/audience/secret.
- SQLx Postgres pool using `connect_lazy`.
- Reqwest HTTP client with a 10 second client timeout.

The lazy pool means `/v1/health` can report the process is up before the database is
available. `/v1/ready` is the deploy/load-balancer gate because it executes `select 1`.

### Request lifecycle

1. `correlation_id` middleware propagates or creates `x-correlation-id`.
2. `security_headers` middleware adds conservative response headers.
3. Router-level guards bound every request: clients over their `RATE_LIMIT_PER_MINUTE`
   budget get `429 RATE_LIMITED` (error contract + `retry-after`; keyed by the
   proxy-appended rightmost `x-forwarded-for` entry, falling back to the socket peer),
   bodies over `MAX_BODY_BYTES` are rejected `413`, and handling that exceeds
   `REQUEST_TIMEOUT_SECS` returns `503` (retriable — Stripe re-delivers webhooks and
   processing is idempotent). Guard responses still carry the correlation and security
   headers.
4. Customer/admin extractors parse `Authorization: Bearer <jwt>`.
5. The matching JWT validator checks signature, issuer, audience, and expiry.
6. New customers call `POST /v1/account/provision`; this validates the Supabase JWT and
   creates or returns the ForgeCustomer business customer row for the token subject.
7. Customer requests resolve `auth_user_id` to a ForgeCustomer business customer row.
8. `CustomerContext::require_active()` fails closed for missing profiles or suspended
   customers.
9. Handlers call repositories/services and return either JSON success or the shared error
   contract.

### Route implementation status

All routes are fully implemented; auth boundaries (customer vs operator, role-gated
mutations) are enforced ahead of all data access. Any new endpoint ships with its
transaction, audit write, outbox behavior, and tests in the same change.

### Background worker

The outbox worker polls pending events on a fixed interval and publishes through the
DataForge client. Retry backoff is deterministic and dead-letters after a fixed maximum
attempt count. Event publishing must remain asynchronous to the customer transaction.

---

## 4. API Contract

The HTTP API uses JSON over HTTPS with base path `/v1`. The machine-readable contract is
`contracts/openapi.yaml`; the router implementation is in `api/src/routes`.

### Public routes

| Route | Status | Purpose |
| --- | --- | --- |
| `GET /v1/health` | implemented | Process liveness: `{ "status": "ok" }`. |
| `GET /v1/ready` | implemented | Database readiness; returns 503 when DB is unreachable. |
| `GET /v1/version` | implemented | Service name, crate version, `GIT_SHA`, and `APP_ENV`. |
| `GET /v1/products` | implemented | Active product catalog rows. |
| `GET /v1/plans` | implemented | Active plan rows. |
| `GET /v1/entitlements/keys` | implemented | Published Ed25519 verification keys. |
| `POST /v1/webhooks/stripe` | implemented processing layer | Verifies Stripe signature, parses a minimal event envelope, stores/dedupes by Stripe event id, ignores unsupported events, and transactionally applies supported checkout/subscription/invoice state with audit + outbox + subscription-linked license sync. |

### Customer routes

Customer routes require a valid Supabase JWT and an active ForgeCustomer customer profile.
The exception is `POST /v1/account/provision`, which requires a valid Supabase JWT but
does not require an existing profile because it is the controlled profile-creation flow.
Current route surface:

- `GET /v1/account`
- `POST /v1/account/provision`
- `GET|POST /v1/account/deletion-request`
- `POST /v1/account/deletion-request/cancel`
- `GET /v1/subscriptions`
- `GET /v1/licenses`
- `GET /v1/installations`
- `POST /v1/installations`
- `POST /v1/installations/{id}/activate`
- `POST /v1/installations/{id}/heartbeat`
- `POST /v1/installations/{id}/deactivate`
- `GET /v1/devices`
- `GET /v1/entitlements/current`
- `POST /v1/entitlements/check`
- `POST /v1/entitlements/offline-lease`
- `POST /v1/usage/check`
- `POST /v1/usage/reserve`
- `POST /v1/usage/commit`
- `POST /v1/usage/release`
- `GET /v1/usage/current`
- `POST /v1/checkout`

`POST /v1/account/provision` creates or returns the caller's business customer profile
idempotently, writes the initial status-history receipt, and queues the sanitized
`customer_created` outbox event for newly-created profiles. `GET /v1/account` returns
the resolved customer/auth identifiers; `GET /v1/subscriptions` returns the caller's
subscription projections. Every customer handler is implemented.

The deletion surface is implemented: customers open, read, and cancel their deletion
request (`/v1/account/deletion-request*`; cancel is clean until processing); operators
drive `requested → verified → cooling_off → processing` and execute the anonymization
from processing (`/v1/admin/deletion-requests/*`). Execution is one transaction —
profile PII anonymized, emails deleted, devices and licenses revoked with explicit
records, installations deactivated, PII-free receipt written, `customer_anonymized`
queued, `deletion_completed` audited — and refuses while a non-terminal subscription
remains. Anonymized accounts fail closed at the auth boundary.

The usage surface is implemented: advisory `check`; idempotent `reserve` under a
per-(customer, meter, period) lock with explainable `quota_decisions` rows and
reservation expiry (lazy + background sweeper); `commit` converting reservations or
directly charging with quota gating, never double-charging on replay, and queueing
threshold/commit-failed outbox events; idempotent `release`; and `current` totals with
limits and remaining quota.

The entitlement surface is implemented: `GET /v1/entitlements/current` assembles the
caller's entitlements (included-plan baseline → subscription plan → license grants →
promotional grants → admin overrides, with cloud gating and fail-closed denials), signs
the snapshot with the active Ed25519 key, stores it for audit/replay, and returns it
with wire field order matching the canonical signing order. `POST /v1/entitlements/check`
answers an advisory feature or quota question read-only and fail-closed.
`POST /v1/entitlements/offline-lease` issues a stored, audited, signed `forge.lease.v1`
document for an activated installation and refuses suspended, non-active-license, and
revoked contexts.

The licensing surface is implemented: `POST /v1/installations` registers idempotently by
client install key (optionally registering an Ed25519 device public key);
`POST /v1/installations/{id}/activate` links a license to the installation under a row
lock, enforcing the device limit and explicit revocations and failing closed on
non-active licenses; heartbeat records liveness; deactivate releases the installation's
activations; and the `GET` listings return the caller's own installations, devices, and
licenses (with active device counts).

`POST /v1/checkout` is implemented for active customers. It resolves the active paid
catalog plan server-side, creates a Stripe Checkout Session, stores the returned Stripe
session id in `checkout_sessions`, and returns the hosted checkout URL. It does not
activate subscriptions or entitlements.

### Admin routes

Admin routes require an **EdDSA** operator JWT minted by **Forge Command's Token Authority**
(issuer `ADMIN_JWT_ISSUER`, e.g. `forge_command_local`; audience `ADMIN_JWT_AUDIENCE`, e.g.
`forgecustomer-admin`), verified against Forge Command's published Ed25519 **public key**
(`ADMIN_JWT_PUBLIC_KEY`) — there is no shared admin secret. The admin role is carried as
`roles=["admin"]` or the capability `scope` (e.g. `admin`). A valid customer token (Supabase
HS256) must never satisfy an admin extractor.

Current route surface:

- `GET /v1/admin/customers`
- `POST /v1/admin/customers/{id}/suspend`
- `POST /v1/admin/customers/{id}/restore`
- `POST /v1/admin/subscriptions/{id}/resync`
- `POST /v1/admin/licenses`
- `POST /v1/admin/licenses/{id}/revoke`
- `POST /v1/admin/entitlements/override`
- `POST /v1/admin/usage/adjust`
- `GET /v1/admin/audit`
- `GET /v1/admin/deletion-requests`
- `POST /v1/admin/deletion-requests/{id}/advance`
- `POST /v1/admin/deletion-requests/{id}/reject`
- `POST /v1/admin/deletion-requests/{id}/execute`

The admin surface is implemented and is the Forge Command integration point. Reads
require any valid operator token; mutations require the `admin` role and a written
reason, write operator-actor commercial audit, preserve append-only ledgers (usage
corrections are compensating `adjustment` events behind a required idempotency key), and
queue the contract-defined outbox events (`customer_suspended`, `customer_restored`,
`license_revoked`). Subscription resync pulls current truth from the Stripe API,
reprojects it, syncs the linked license, and advances the event watermark so stale
out-of-order webhooks are subsequently skipped. Suspend/restore and revoke are
idempotent and report `changed: false` on replay.

### Error contract

Every API error renders as:

```json
{
  "error": {
    "code": "UNAUTHENTICATED",
    "message": "Missing Authorization header.",
    "correlation_id": "corr_...",
    "details": {}
  }
}
```

Representative stable codes:

```text
UNAUTHENTICATED
INVALID_TOKEN
TOKEN_EXPIRED
WRONG_AUDIENCE
FORBIDDEN
CUSTOMER_SUSPENDED
NOT_FOUND
CONFLICT
IDEMPOTENCY_REPLAY
VALIDATION_FAILED
QUOTA_EXCEEDED
DEVICE_LIMIT_REACHED
REVOKED
RATE_LIMITED
SERVICE_UNAVAILABLE
NOT_IMPLEMENTED
INTERNAL
```

Database errors are logged server-side and mapped to `INTERNAL` without leaking database
details to the client.

Router-level guards respond before handlers run. Clients exceeding their per-minute
budget get `429 RATE_LIMITED` through the standard envelope with a `retry-after` header.
Two guards return plain (non-enveloped) responses: bodies over `MAX_BODY_BYTES` are
rejected `413`, and requests exceeding `REQUEST_TIMEOUT_SECS` return `503`. All guard
responses still carry the correlation and security headers.

### Idempotency and correlation

- Every response includes `x-correlation-id`.
- Clients may provide `x-correlation-id` (up to 128 chars of `[A-Za-z0-9._-]`, since the
  value lands in audit rows and logs); anything else — or no header — yields a generated
  `corr_<uuid>`.
- Mutating endpoints that can be retried should accept `Idempotency-Key`.
- Usage, installation, Stripe webhook, and outbox delivery paths must treat replay as
  expected behavior, not as an exceptional production incident.

---

## 5. Data Model

Supabase/PostgreSQL is the authoritative store for customer and commercial state. The
schema is additive and deterministic under `supabase/migrations`.

### Migration domains

| Migration | Domain | Primary tables |
| --- | --- | --- |
| `0001_customer_identity.sql` | Customer identity projection | `customer_profiles`, `customer_status_history`, `customer_emails` |
| `0002_product_catalog.sql` | Product catalog | `products`, `product_versions`, `features`, `plans`, `plan_versions`, `plan_features`, `plan_quotas`, `release_channels` |
| `0003_commerce.sql` | Commerce and Stripe projection | `billing_accounts`, `stripe_customers`, `subscriptions`, `subscription_items`, `billing_periods`, `checkout_sessions`, `invoice_references`, `stripe_webhook_events` |
| `0004_licensing.sql` | Licenses, installations, devices | `licenses`, `license_grants`, `devices`, `installations`, `license_activations`, `license_leases`, `license_revocations` |
| `0005_entitlements.sql` | Entitlements | `entitlement_grants`, `entitlement_overrides`, `entitlement_snapshots` |
| `0006_usage.sql` | Usage and quotas | `usage_meters`, `usage_reservations`, `usage_events`, `usage_period_totals`, `quota_decisions` |
| `0007_audit_outbox.sql` | Audit and outbox | `commercial_audit_events`, `outbox_events` |
| `0008_privacy.sql` | Privacy and deletion | `policy_versions`, `consent_records`, `account_deletion_requests` |
| `0009_rls.sql` | Row-level security | Enables and forces RLS; creates own-row and public-catalog policies. |
| `0010_seed_constraints.sql` | Determinism and indexes | Adds seed/constraint hardening and operational indexes. |

### RLS posture

RLS is enabled and forced across public tables. Customer-facing records are scoped by the
business `customer_id`, not only by the Supabase auth subject. Catalog tables are public
read. CI asserts that all public tables have RLS enabled.

The API still owns privileged writes. RLS is defense in depth, not a substitute for the
server-side authorization model.

### Append-only state

Append-only tables are part of the commercial trust boundary:

- `usage_events`
- `commercial_audit_events`
- webhook/event receipt tables where replay protection matters
- outbox delivery records, except operational status fields required for retry/dead-letter

Corrections must be represented by new compensating events, never by silently editing the
authoritative ledger.

### Catalog seed model

Products, plan versions, features, quotas, and release channels are seeded
deterministically. Adding a future product should be data-first: insert product/catalog
rows and only add schema when a genuinely new domain concept exists.

### Repository layer

The Rust API uses SQLx runtime query APIs. The crate does not require a live database for
compile-time query macro verification. Repository functions currently cover customer
profile lookup and catalog list operations; additional DB-backed endpoints should add
repository functions rather than embedding ad hoc SQL in route handlers.

---

## 6. Domain Subsystems

The service separates pure domain rules from route wiring. Pure logic is testable without
Stripe, Supabase, or a live database.

### Customer identity

Supabase Auth owns login identity. ForgeCustomer owns business customer profiles and
status. Customer route access requires:

1. Valid Supabase JWT.
2. Token subject parseable as a UUID.
3. Matching `customer_profiles.auth_user_id`.
4. Non-suspended status for privileged product actions.

Missing profile fails closed as `FORBIDDEN`.

Profile provisioning is the controlled exception: `POST /v1/account/provision` validates
the Supabase JWT, inserts one `customer_profiles` row for the token subject, writes an
initial `customer_status_history` row, projects the trusted Supabase email claim into
`customer_emails` when present, and returns the existing profile on repeat calls. The
endpoint accepts only display/localization decoration; customer type and commercial status
remain server-owned.

### Commerce and Stripe

Stripe owns payment processing. ForgeCustomer stores normalized subscription projection
used by product clients.

Current pure logic maps Stripe subscription statuses into ForgeCustomer statuses and
determines whether a status grants cloud access. Checkout creation is live for active paid
catalog plans: the API resolves `plan_versions.stripe_price_id`, calls Stripe with the
server-side secret, stores the returned session id, and returns the hosted URL. Webhook
processing is also live: the API verifies `Stripe-Signature`, parses a minimal non-PII
event summary, stores the event id once, marks unsupported events ignored, and applies
supported checkout/subscription/invoice events in one transaction. Subscription changes
write normalized projection rows, commercial audit, and sanitized `subscription_changed`
outbox events. Only verified Stripe webhooks may change subscription truth; browser
redirects must only confirm that the customer returned from Stripe.

### Licensing and installations

The model keeps licenses, installations, devices, activations, leases, and revocations as
distinct concepts.

Implemented behavior:

- Subscription-linked licenses are issued and kept in sync by verified webhook processing
  only: cloud-granting statuses issue/reactivate, `past_due` is a dunning grace window,
  `unpaid`/`paused`/`incomplete` suspend, `canceled` expires, and a revoked license is
  never changed by subscription state. The device limit comes from the plan version's
  `<product>.devices.max` feature (default 1).
- Registration is idempotent by client-supplied install key; an optional base64 Ed25519
  public key (validated to 32 bytes, fingerprinted with SHA-256) upserts device identity.
  Re-registering a deactivated installation reactivates the installation record only.
- Activation locks the license row, then fails closed in order: deactivated installation,
  revoked device, revoked/suspended/expired license, explicit `license_revocations` row
  (license-, installation-, or device-scoped), and finally the device limit. An
  already-active pairing returns idempotently.
- Customers deactivate old installations to free slots; deactivation releases the
  installation's active activations.
- Activation, deactivation, and every license sync mutation write commercial audit;
  registration and activation also queue sanitized outbox events.
- Offline leases are time-bound and denied for suspended or revoked contexts; lease
  issuance wiring lands with the entitlement snapshot work.

### Entitlements

Entitlements are evaluated deterministically from lower-precedence defaults to
higher-precedence overrides:

```text
product defaults
  -> plan version features and quotas
  -> active subscription cloud gates
  -> license grants
  -> promotional grants
  -> admin overrides
  -> suspension/revocation denials
  -> signed entitlement snapshot
```

Suspension and revocation always deny cloud/new-lease capabilities. Local product access
is evaluated independently and must not be revoked by commercial state.

Implemented behavior:

- Snapshot assembly maps the layers onto data: the product's `<product>_included` plan
  is the baseline; the current subscription (cloud-granting preferred, canceled excluded)
  contributes its plan version; license grants come from active unexpired licenses;
  promotional grants and admin overrides apply last. Quota limits merge in the same
  order, and monthly meters surface committed usage as `<meter>.used`.
- Suspension is rejected at the auth boundary (`CUSTOMER_SUSPENDED`); a revoked latest
  license forces cloud features off in evaluation.
- `Signer25519` signs canonical snapshots and leases; `VerifyingKeyRing` verifies and
  `GET /v1/entitlements/keys` publishes active verification keys. Issued snapshots are
  stored in `entitlement_snapshots`; responses preserve the canonical field order so
  clients can verify the signature from the received document.
- Advisory feature/quota checks are read-only and fail closed.
- Offline leases (`forge.lease.v1`) are issued only to active installations holding an
  active activation on an active, unexpired license, with no revocation in scope; each
  issuance stores the lease row and a `lease_issued` audit event transactionally. Lease
  lifetime is the configured offline grace window.

### Usage and quotas

Usage accounting is ledger-first:

- `usage_events` is authoritative and append-only.
- `usage_period_totals` is a rebuildable optimization.
- `usage_reservations` holds in-flight quota.
- `quota_decisions` records explainable allow/deny decisions.
- Meter units must be explicit.

Implemented behavior:

- Limits resolve from the assembled entitlement quotas (cadence-qualified key first);
  uncataloged quota rows leave a meter uncapped, while the included plan zeroes the paid
  meters for free customers.
- Reserve and direct commit share one decision path under a `(customer, meter, period)`
  totals lock; every decision (allow and deny) is recorded in `quota_decisions`.
- Reservations dedupe on `(customer, idempotency key)`, commits dedupe the same pair in
  the ledger; replays return the original row and never double-charge.
- Stale pending reservations expire lazily inside that lock and via the
  `workers::usage` background sweeper; committing an expired reservation fails closed
  and frees its hold.
- Threshold crossings queue `quota_threshold_reached` once per
  (customer, meter, period, threshold); denied direct commits queue
  `usage_commit_failed`.
- Period totals are derived and were verified live to equal the ledger sum.

### Privacy and deletion

The schema includes policy versions, consent records, and account deletion requests.

Implemented behavior:

- The state machine (`requested → verified → cooling_off → processing → completed`,
  with `rejected`/`canceled` terminals) is pure logic in `domain::deletion`; customers
  request and cancel, operators advance, reject, and execute.
- Cooling-off is non-destructive so a customer cancel restores nothing; the window is
  stamped on entry and entering `processing` fails closed while it has not elapsed.
- Execution anonymizes in one transaction — profile PII, contact emails, device labels
  (devices revoked), licenses revoked with explicit revocation records, installations
  deactivated, overrides deactivated — writes a PII-free receipt with the retention
  exceptions, queues the sanitized `customer_anonymized` event, and audits
  `deletion_completed`. It refuses while a non-terminal subscription remains.
- Legally required accounting records (billing/invoice references, audit, usage ledger,
  consent records) are retained per `docs/PRIVACY.md`; anonymized accounts fail closed
  at the auth boundary.

### Admin operations

Admin APIs use a separate operator issuer and audience (Forge Command). Every
implemented admin mutation:

- Validates operator authorization (mutations additionally require the `admin` role).
- Requires a written reason for material commercial changes.
- Writes operator-actor commercial audit.
- Preserves append-only ledgers (usage corrections are compensating adjustment events
  behind a required idempotency key).
- Emits a sanitized outbox event where the event contract defines one.

---

## 7. Integrations and Events

ForgeCustomer integrates with Supabase, Stripe, DataForge, and product clients. Each
integration is constrained by the authority boundaries in this document.

### Supabase

Supabase supplies Auth and PostgreSQL. ForgeCustomer validates Supabase JWTs locally using
the configured HS256 secret, issuer, and audience. PostgreSQL migrations live in this repo
and are applied to the selected Supabase project.

The Supabase service-role key is server-side only. Customer products and browser code
must never receive it.

### Stripe

Stripe integration rules:

- `STRIPE_SECRET_KEY` is server-side only.
- Checkout creation resolves Stripe price ids from the catalog; clients provide product
  and plan keys, never raw Stripe price ids.
- `STRIPE_WEBHOOK_SECRET` verifies webhook signatures.
- Webhook verification uses HMAC-SHA256 and constant-time comparison.
- Duplicate and replayed webhook events are expected and must be idempotent.
- The webhook route stores verified event envelopes once in `stripe_webhook_events` and
  applies supported checkout/subscription/invoice events transactionally.
- Raw card data is never stored.
- Raw webhook payload retention must be minimal and access-restricted.

Checkout creation, signature verification, event parsing, idempotent receipt, subscription
projection, invoice references, audit writes, sanitized subscription outbox emission, and
subscription-linked license sync exist. Entitlement snapshot assembly from those projected
rows remains a later phase.

### DataForge outbox

DataForge receives sanitized operational/commercial evidence through `outbox_events`.
DataForge is a sink, not a source of truth.

Outbox behavior:

- Customer transaction writes state, audit, and outbox rows in one database transaction.
- Background worker publishes pending rows to DataForge.
- DataForge failures do not roll back customer transactions.
- Retry uses deterministic backoff and eventually dead-letters exhausted events.
- Delivery keys must make repeated publishes idempotent downstream.

Every event in the contract has a live emit site: `customer_created` (provisioning),
`subscription_changed` (webhook processing and admin resync, when the projection
changed), `installation_registered` (first registration), `license_activated`
(successful activation), `license_revoked` (admin revocation), `customer_suspended` /
`customer_restored` (admin status changes), `quota_threshold_reached` (usage commits
crossing configured thresholds, once per customer/meter/period/threshold),
`usage_commit_failed` (denied direct commits), and `customer_anonymized` (deletion
execution, keyed by request id).

### Event payload hygiene

Outbox payloads must not contain:

- Email, full name, direct customer PII.
- Stripe customer IDs, card/payment details, raw webhook payloads.
- Passwords, sessions, refresh tokens, service-role keys, API keys, signing keys.
- Manuscript content, prompt content, model output, diagnostics, repair findings, or
  creative project content.

Permitted identifiers are pseudonymous IDs such as `customer_id`, `installation_id`, and
product/plan keys when they do not reveal direct PII.

The event schema is `contracts/events/outbox-event-v1.schema.json`; the API also enforces
redaction with `domain::redaction` and `integrations::dataforge`.

### Contracts

Contracts live under `contracts/`:

- `openapi.yaml` for HTTP routes.
- `entitlement-v1.schema.json` for signed entitlement snapshots.
- `lease-v1.schema.json` for signed offline leases.
- `events/outbox-event-v1.schema.json` for DataForge outbox delivery envelopes.

CI validates OpenAPI with Redocly and checks JSON schema files parse.

---

## 8. Security and Privacy

ForgeCustomer is a fail-closed commercial authority. Security decisions must be explicit,
testable, and boring.

### Token validation

Customer tokens:

- Supabase-issued JWTs.
- Validated for HS256 signature, issuer, audience, and expiry.
- `sub` must parse as a UUID.
- Missing or unprovisioned customer profiles fail closed.

Admin tokens:

- Separate operator issuer and audience.
- Separate secret from customer tokens.
- A customer token cannot authorize an admin route.

If a JWT secret is absent, the validator is marked unconfigured and rejects tokens. That
prevents accidental local or production token acceptance.

### Secrets

Server-side only:

- `SUPABASE_SERVICE_ROLE_KEY`
- `SUPABASE_JWT_SECRET`
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `ENTITLEMENT_SIGNING_PRIVATE_KEY`
- `DATAFORGE_SERVICE_TOKEN`

Secrets must not appear in clients, logs, docs examples with real values, outbox payloads,
or repo history.

### Security headers

Every response receives:

- `x-content-type-options: nosniff`
- `x-frame-options: DENY`
- `referrer-policy: no-referrer`
- `strict-transport-security: max-age=31536000; includeSubDomains`

### Entitlement signing

Entitlement snapshots use Ed25519. The signing private key is loaded from
`ENTITLEMENT_SIGNING_PRIVATE_KEY`, and published keys are exposed by key ID. Key rotation
requires an overlap window where old and new public keys both verify existing snapshots.

Forged snapshots must fail verification. Private signing keys must never be logged.

### PII classification

| Class | Examples | Handling |
| --- | --- | --- |
| Direct PII | email, full name | RLS, redaction, no outbox payloads |
| Financial references | Stripe customer/payment identifiers | server-side only, no outbox payloads |
| Pseudonymous IDs | `customer_id`, `installation_id`, device public key | allowed in sanitized events |
| Secrets | API keys, JWT secrets, signing private key | secret manager/env only |
| Creative content | manuscripts, prompts, model output | never stored here |

### Failure doctrine

- Auth failure denies.
- Suspended customers receive no privileged product actions.
- Revoked devices receive no new activations/leases.
- Ambiguous entitlement state denies cloud/new lease access.
- Local creative access must remain available despite cloud, billing, or DataForge
  outages.
- DataForge outage degrades to queued outbox delivery, not failed customer transactions.

---

## 9. Configuration and Operations

Configuration is loaded from environment variables in `api/src/config.rs`. Missing
required variables fail startup. Empty token-verification secrets fail token validation.

### Core environment variables

| Variable | Required for startup | Default | Purpose |
| --- | --- | --- | --- |
| `APP_ENV` | no | `development` | Environment label returned by `/v1/version`. |
| `HOST` | no | `0.0.0.0` | Bind host. |
| `PORT` | no | `8080` | Bind port. |
| `DATABASE_URL` | yes | none | Postgres/Supabase database URL. |
| `SUPABASE_JWT_ISSUER` | yes | none | Customer JWT issuer. |
| `SUPABASE_JWT_AUDIENCE` | no | `authenticated` | Customer JWT audience. |
| `SUPABASE_JWT_SECRET` | required to accept customer tokens | empty | Customer JWT HS256 verification secret. |
| `ADMIN_JWT_ISSUER` | yes | none | Operator token issuer (Forge Command Token Authority, e.g. `forge_command_local`). |
| `ADMIN_JWT_AUDIENCE` | yes | none | Operator token audience (e.g. `forgecustomer-admin`). |
| `ADMIN_JWT_PUBLIC_KEY` | required to accept admin tokens | empty | PEM-encoded Ed25519 (SPKI) **public** key that verifies operator JWTs minted by Forge Command. No shared secret. |
| `STRIPE_SECRET_KEY` | required for checkout/webhook work | empty | Stripe API secret. |
| `STRIPE_WEBHOOK_SECRET` | required for webhook work | empty | Stripe webhook verification secret. |
| `ENTITLEMENT_SIGNING_PRIVATE_KEY` | yes | none | Base64 Ed25519 seed for snapshot signing. |
| `ENTITLEMENT_SIGNING_KEY_ID` | no | `entitlement-key-1` | Published signing key ID. |
| `DATAFORGE_API_URL` | no | empty | Enables outbox worker when set. |
| `DATAFORGE_SERVICE_TOKEN` | no | empty | DataForge service bearer token. |
| `ENTITLEMENT_SNAPSHOT_TTL_HOURS` | no | `24` | Snapshot lifetime. |
| `OFFLINE_GRACE_DAYS` | no | `14` | Offline grace window. |
| `REQUEST_TIMEOUT_SECS` | no | `30` | Per-request deadline enforced by the router; expiry returns `503`. |
| `MAX_BODY_BYTES` | no | `1048576` | Request body cap enforced by the router; oversized bodies return `413`. |
| `RATE_LIMIT_PER_MINUTE` | no | `300` | Per-client (per-IP) request budget per minute; exceeding it returns `429 RATE_LIMITED` with `retry-after`. `0` disables. |

`.env.example` is a template only. Real values must come from a secret manager or the
deployment environment.

### Local build and run

```bash
cp .env.example .env
cargo build --all
cargo test --all
cargo run -p forgecustomer-api
```

For a local Supabase development database:

```bash
supabase db reset
```

For an existing target project:

```bash
supabase db push
```

### Deployment checklist

1. Select the correct Supabase project for dev, staging, or production.
2. Apply migrations and deterministic seed data.
3. Configure secrets for that environment only; never reuse production secrets in lower
   environments.
4. Build the API release binary.
5. Start the process with `HOST`, `PORT`, and required secrets.
6. Verify `/v1/health`, `/v1/ready`, and `/v1/version`.
7. Configure Stripe webhook endpoint only after `STRIPE_WEBHOOK_SECRET` is set.
8. Confirm DataForge outbox worker behavior when `DATAFORGE_API_URL` is configured.

### Operational probes

- `/v1/health` means the process is running.
- `/v1/ready` means the database can answer `select 1`.
- `/v1/version` identifies service, crate version, git SHA if injected, and environment.

Load balancers should gate on readiness, not liveness.

### Runbook references

Detailed operational notes remain in `docs/RUNBOOK.md`. Domain-specific references remain
in `docs/STRIPE.md`, `docs/LICENSING.md`, `docs/ENTITLEMENTS.md`, `docs/USAGE.md`, and
`docs/PRIVACY.md`.

---

## 10. Verification and Status

The current proof layer is a mix of Rust tests, migration validation, contract linting,
schema parsing, secret scanning, and dependency audit.

### Local verification

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
bash doc/system/BUILD.sh
```

The API uses SQLx runtime query APIs, so Rust build/test does not require a live database.
Migration and RLS validation require PostgreSQL or the CI migration job.

### CI gates

| Job | Checks |
| --- | --- |
| `rust` | `cargo fmt --all --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all` |
| `migrations` | Postgres 16 migration apply, deterministic reapply, seed idempotency, RLS coverage, append-only ledger update rejection |
| `contracts` | Redocly OpenAPI lint, JSON schema parse checks |
| `secret-scan` | Gitleaks over repo history |
| `audit` | `cargo audit` |

### Tests covered today

- JWT validator accepts valid tokens and rejects expired, wrong-audience, wrong-issuer,
  bad-signature, and unconfigured-secret cases.
- Bearer header parsing.
- Checkout request validation and Stripe Checkout Session form construction.
- Stripe checkout/subscription/invoice event extraction for webhook processing.
- Account provisioning input validation and customer-auth boundary.
- Installation registration validation: install key shape, Ed25519 public-key decode and
  fingerprint stability, app version, and device label rules.
- License sync transitions: issuance on cloud-granting status, past-due grace, suspension,
  expiry, reactivation, and that revoked licenses never auto-lift.
- Entitlement check-key validation and signed-lease canonical bytes (signature excluded,
  stable, sign/verify/tamper roundtrip).
- Entitlement snapshot, check, and offline-lease routes fail closed without auth; the
  keys endpoint stays public.
- Admin input validation: reason bounds, device-limit bounds, adjustment amount
  (finite/non-zero/bounded), period-key shape and window, typed override values.
- Admin role boundary: operator tokens without the `admin` role are rejected (403) on
  every mutation; reads pass; reason validation rejects before any database write; usage
  adjustments without an idempotency key are rejected.
- Usage domain rules: amount bounds, cadence period keys, quota-key candidate order, and
  threshold-crossing detection (fires exactly on crossing, never re-fires, never for
  unlimited/zero limits).
- All five usage routes fail closed without auth.
- Deletion state machine: linear forward path, cancel/reject stop at processing,
  execution only from processing; deletion and subscription routes fail closed without
  auth and the admin deletion mutations are role-gated.
- Stripe webhook signature, parsing, missing/bad signature, and malformed signed-envelope
  rejection behavior.
- Customer token cannot access admin route.
- Unauthenticated admin route is rejected.
- All licensing routes (listings, registration, and parameterized
  activate/heartbeat/deactivate) and parameterized admin routes fail closed without auth.
- Valid operator token reaches pending admin handler and returns `NOT_IMPLEMENTED`.
- Public health route requires no token.
- Error responses include the shared error contract and correlation ID.
- Domain/service unit tests cover subscription status normalization, entitlement
  precedence, signing and verification, key-ring behavior, quota decisions, device limit
  checks, offline lease validity, redaction, Stripe webhook verification, DataForge
  publish hygiene, and outbox backoff.

### Known implementation gaps

These are intentional MVP gaps and should not be hidden by documentation:

- End-to-end suites with live or mocked Stripe/Supabase/DataForge flows in CI. The live
  local verification suites (174 checks across licensing, entitlements, usage, admin,
  and deletion against PostgreSQL 16 with a mocked Stripe API) are the blueprint.

### Release standard

A feature is not releasable until it has:

- Route/service/repository implementation.
- Transactional behavior for state, audit, and outbox where relevant.
- Auth and RLS boundary tests.
- Idempotency or replay tests for retried operations.
- Contract/doc updates in the same change.
- A passing local or CI proof appropriate to the feature.

---

## 11. Governance and Change Control

This repository treats documentation as part of the system contract. Changes that alter
customer/commercial behavior must update this canonical source tree and any supporting
contract files in the same change.

### Canonical doc workflow

1. Edit the relevant file under `doc/system/`.
2. Rebuild with `bash doc/system/BUILD.sh`.
3. Review `doc/FOCSYSTEM.md`.
4. Run the relevant Rust, migration, and contract checks.

Do not edit `doc/FOCSYSTEM.md` directly except as a generated output from the build
script.

### Supporting docs

The existing `docs/` tree remains useful for domain detail. It is not the generated
canonical artifact. When domain docs and `doc/FOCSYSTEM.md` diverge, update both or
record why the domain doc is stale.

### Change boundaries

Any change that does one of the following requires a documentation update:

- Adds or removes an API route.
- Changes auth, admin, customer, RLS, or token validation behavior.
- Adds a table, migration, event type, schema, or outbox payload field.
- Changes Stripe, DataForge, Supabase, signing, privacy, or deletion behavior.
- Marks a `NOT_IMPLEMENTED` route as implemented.
- Changes local-access/offline entitlement doctrine.

### Review checklist

- Authority matrix still has no overlap.
- Secrets remain server-side only.
- DataForge remains a sanitized sink.
- Usage and audit state remain append-only.
- Creative content remains out of scope.
- CI and local proof match the claims in this document.
