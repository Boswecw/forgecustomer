# API.md — ForgeCustomer HTTP API

Base path: `/v1`. Transport: JSON over HTTPS. The machine-readable contract is
`contracts/openapi.yaml`.

## Conventions

- **Authentication**: `Authorization: Bearer <jwt>`. Customer routes accept Supabase
  JWTs; `/v1/admin/*` requires an operator JWT from the admin issuer.
- **Correlation**: every response includes `X-Correlation-Id`. Clients may send one via
  `X-Correlation-Id`; otherwise the server generates one.
- **Idempotency**: mutating endpoints accept `Idempotency-Key`. Usage operations require
  a stable key to make retries safe; installation registration is idempotent on the
  client-supplied `install_key`, and activation is idempotent per (license, installation).
- **Limits**: request bodies are size-limited; requests are rate-limited and time-limited.

## Error contract

All errors share this shape:

```json
{
  "error": {
    "code": "CUSTOMER_SUSPENDED",
    "message": "This customer account is suspended.",
    "correlation_id": "corr_01H...",
    "details": {}
  }
}
```

Representative codes: `UNAUTHENTICATED`, `INVALID_TOKEN`, `TOKEN_EXPIRED`,
`WRONG_AUDIENCE`, `FORBIDDEN`, `BAD_REQUEST`, `CUSTOMER_SUSPENDED`, `NOT_FOUND`, `CONFLICT`,
`IDEMPOTENCY_REPLAY`, `VALIDATION_FAILED`, `QUOTA_EXCEEDED`, `DEVICE_LIMIT_REACHED`,
`REVOKED`, `RATE_LIMITED`, `INTERNAL`.

## Route groups

| Group                  | Purpose                                             | Auth      |
| ---------------------- | --------------------------------------------------- | --------- |
| `GET /v1/health`       | liveness                                            | none      |
| `GET /v1/ready`        | readiness (DB reachable)                            | none      |
| `GET /v1/version`      | build/version info                                  | none      |
| `/v1/account`          | provision/read own profile, consent, deletion requests | customer  |
| `/v1/products`         | public product catalog                              | optional  |
| `/v1/plans`            | public plan catalog                                 | optional  |
| `/v1/subscriptions`    | own subscription summary                            | customer  |
| `/v1/licenses`         | own licenses                                        | customer  |
| `/v1/installations`    | register / list / activate / heartbeat / deactivate | customer  |
| `/v1/devices`          | own devices                                         | customer  |
| `/v1/entitlements`     | current / check / offline-lease                     | customer  |
| `/v1/usage`            | check / reserve / commit / release / current        | customer  |
| `/v1/checkout`         | create Stripe Checkout session                      | customer  |
| `/v1/webhooks/stripe`  | Stripe webhook receiver                             | signature |
| `/v1/admin/*`          | operator administration                             | operator  |

See `docs/LICENSING.md`, `docs/ENTITLEMENTS.md`, `docs/USAGE.md`, `docs/STRIPE.md` for the
per-domain endpoint semantics, and Phase 10 of the plan for the admin surface.

## Health, ready, version

- `GET /v1/health` → `{ "status": "ok" }` (process is up).
- `GET /v1/ready` → `200` when the database is reachable, else `503`.
- `GET /v1/version` → `{ "service", "version", "git_sha", "app_env" }`.

## Account provisioning

`POST /v1/account/provision` is the controlled API-owned profile creation flow for a
Supabase-authenticated user. It validates the customer JWT but does **not** require an
existing ForgeCustomer profile. The server creates one business customer row for the
token subject, writes the initial status history receipt, projects the trusted Supabase
email claim when present, and returns the existing row on repeat calls.

Clients may submit only profile decoration:

```json
{
  "display_name": "Ada Lovelace",
  "country_code": "US",
  "timezone": "America/Kentucky/Louisville"
}
```

Customer type, status, commercial records, licenses, entitlements, and usage state are
server-owned and cannot be set by this endpoint.

## Licensing: installations, devices, licenses

See `docs/LICENSING.md` for the full rules. Summary of the live endpoints:

- `POST /v1/installations` registers an installed application instance, idempotent on the
  client-supplied `install_key` (8–120 chars of `[A-Za-z0-9._:-]`). An optional
  `device_public_key` (base64 32-byte Ed25519 public key) registers the device identity;
  the private key never leaves the client. Re-registering a deactivated installation
  reactivates the installation record; license slots are only consumed by activation.
  First registration queues a sanitized `installation_registered` outbox event.
- `GET /v1/installations`, `GET /v1/devices`, `GET /v1/licenses` list the caller's own
  rows (licenses include `device_limit` and the current `active_devices` count).
- `POST /v1/installations/{id}/activate` links a license to the installation. With no
  `license_id` in the body, the most recently issued active license for the
  installation's product is used. Fails closed: suspended/expired licenses → `403
  FORBIDDEN`, revoked licenses / revoked devices / explicit `license_revocations` rows →
  `403 REVOKED`, full license → `402 DEVICE_LIMIT_REACHED` (details carry
  `device_limit` and `active_devices`). The license row is locked during activation so
  concurrent requests cannot oversubscribe the limit. Re-activating an already-active
  pairing returns `already_active: true`. Writes a `license_activated` audit event and
  outbox event.
- `POST /v1/installations/{id}/heartbeat` records liveness (`last_heartbeat_at`) and may
  refresh the reported `app_version`.
- `POST /v1/installations/{id}/deactivate` deactivates the installation and releases its
  active activations, freeing device slots (idempotent). Writes an
  `installation_deactivated` audit event.

## Entitlements: snapshots, checks, offline leases

See `docs/ENTITLEMENTS.md` for the evaluation model. Summary of the live endpoints:

- `GET /v1/entitlements/current` assembles, signs (Ed25519), stores, and returns the
  caller's entitlement snapshot (`forge.entitlements.v1`). Optional `?installation_id=`
  binds the snapshot to an owned installation; `?product_key=` selects the product
  (default `authorforge`). The wire field order matches the canonical signing order so
  clients can verify the signature from the received document and the keys published at
  `GET /v1/entitlements/keys`.
- `POST /v1/entitlements/check` is an advisory, read-only check of exactly one
  `feature_key` or `quota_key` (with optional `amount`). Fails closed: absent features
  and over-quota meters answer `allowed: false`.
- `POST /v1/entitlements/offline-lease` issues a signed `forge.lease.v1` document for an
  activated installation, valid for the offline grace window. Fails closed on
  deactivated installations (`409`), missing activations (`409`), non-active licenses
  (`403 FORBIDDEN`), and revoked devices/licenses/explicit revocation records
  (`403 REVOKED`). Every lease is stored and audited.

## Stripe webhook processing

`POST /v1/webhooks/stripe` verifies `Stripe-Signature` with `STRIPE_WEBHOOK_SECRET`
before parsing or writing any event. Verified events are parsed into a minimal
non-PII summary and stored once in `stripe_webhook_events` by Stripe event id. Duplicate
deliveries return `200` with `duplicate: true`.

Unsupported events are acknowledged and stored as `ignored`. Supported checkout,
subscription, and invoice events apply in one transaction: subscription projection is
normalized, invoice references are recorded, commercial audit is written, a sanitized
`subscription_changed` outbox event is queued when commercial status changes, the
subscription-linked license is issued/suspended/expired/reactivated to match the new
subscription truth (see `docs/LICENSING.md`), and the webhook receipt is marked
`processed`.

## Checkout creation

`POST /v1/checkout` creates a Stripe Checkout Session for an active paid plan. The caller
must be an active ForgeCustomer customer. Clients submit catalog keys and redirect URLs;
the server resolves the active plan version and Stripe price id.

```json
{
  "product_key": "authorforge",
  "plan_key": "authorforge_pro",
  "success_url": "https://example.com/checkout/success",
  "cancel_url": "https://example.com/checkout/cancel"
}
```

The response returns the Stripe-hosted checkout URL and records
`stripe_checkout_session_id` in `checkout_sessions` with status `created`. This does
**not** activate entitlements; verified Stripe webhooks remain the only path that changes
subscription truth.
