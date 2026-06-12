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
| `GET /v1/products/{product_key}/releases/latest` | implemented | Latest published release metadata for a channel. |
| `GET /v1/products/{product_key}/downloads` | implemented | Generic bootstrap artifact lookup for the latest published release. |
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
- `POST /v1/installations/{id}/update-events`
- `GET /v1/updates/authorforge/{target}/{arch}/{current_version}`
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
- `POST /v1/billing-portal`

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

The licensing/update surface is implemented: `POST /v1/installations` registers
idempotently by client install key, assigns the server-resolved default fleet, records
bounded update metadata, and optionally registers an Ed25519 device public key;
`POST /v1/installations/{id}/activate` links a license to the installation under a row
lock, enforcing the device limit and explicit revocations and failing closed on
non-active licenses; heartbeat records liveness; deactivate releases the installation's
activations; and the `GET` listings return the caller's own installations, devices, and
licenses (with active device counts). `GET /v1/updates/authorforge/{target}/{arch}/{current_version}`
is the Tauri-compatible dynamic update endpoint; it resolves fleet from the owned
installation, applies campaign/release/artifact/version/hold/HMAC-rollout gates, returns
`204` for no eligible update, and returns only `{ version, url, signature, notes,
pub_date }` when eligible. `POST /v1/installations/{id}/update-events` stores only
bounded update outcome receipts keyed by UUID `Idempotency-Key`.

`POST /v1/checkout` is implemented for active customers. It resolves the active paid
catalog plan server-side, creates a Stripe Checkout Session, stores the returned Stripe
session id in `checkout_sessions`, and returns the hosted checkout URL. It does not
activate subscriptions or entitlements.

`POST /v1/billing-portal` is the self-service subscription-management door for active
customers (cancel, switch plan, update payment method). It validates the `return_url`,
resolves the caller's linked Stripe customer, mints a **Stripe Billing Customer Portal**
session, and returns `{ "url": ... }` for the browser to follow. It is a *door, not a
mutation*: nothing is persisted and no commercial state changes here — any change the
customer makes in the portal reprojects into ForgeCustomer truth only through the verified
Stripe webhook path. A customer with no Stripe linkage yet (free baseline / never paid)
gets `409 NO_BILLING_ACCOUNT`. Requires the Stripe Customer Portal to be enabled for the
environment (see `docs/STRIPE.md`).

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
- `GET /v1/admin/fleets`
- `GET /v1/admin/fleets/{id}`
- `POST /v1/admin/fleets/{id}/policy`
- `GET /v1/admin/releases`
- `POST /v1/admin/releases`
- `GET /v1/admin/releases/{id}`
- `POST /v1/admin/releases/{id}/artifacts`
- `POST /v1/admin/releases/{id}/validate`
- `POST /v1/admin/releases/{id}/publish`
- `POST /v1/admin/releases/{id}/block`
- `POST /v1/admin/update-campaigns`
- `GET /v1/admin/update-campaigns/{id}`
- `POST /v1/admin/update-campaigns/{id}/pause`
- `POST /v1/admin/update-campaigns/{id}/resume`
- `POST /v1/admin/update-campaigns/{id}/revoke`
- `POST /v1/admin/update-campaigns/{id}/rollout`
- `POST /v1/admin/update-campaigns/{campaign_id}/holds`
- `DELETE /v1/admin/update-campaigns/{campaign_id}/holds/{fleet_id}`
- `GET /v1/admin/update-failures`
- `POST /v1/admin/release-artifacts/{id}/quarantine`
- `GET /v1/admin/deletion-requests`
- `POST /v1/admin/deletion-requests/{id}/advance`
- `POST /v1/admin/deletion-requests/{id}/reject`
- `POST /v1/admin/deletion-requests/{id}/execute`

The admin surface is implemented and is the Forge Command integration point. Reads
require any valid operator token; mutations require the `admin` role and a written
reason, write operator-actor commercial audit, preserve append-only ledgers (usage
corrections are compensating `adjustment` events behind a required idempotency key), and
queue the contract-defined outbox events (`customer_suspended`, `customer_restored`,
`license_revoked`). Fleet/release/campaign mutations also write operator audit and
require idempotency keys for retryable commands. Release validation requires validated
artifact proof; release and immutable artifact metadata can be registered by the
release pipeline through audited admin endpoints before validation/publication. Artifact
quarantine pauses campaigns targeting the affected release.
Subscription resync pulls current truth from the Stripe API,
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
NO_BILLING_ACCOUNT
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
