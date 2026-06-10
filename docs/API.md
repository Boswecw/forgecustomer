# API.md — ForgeCustomer HTTP API

Base path: `/v1`. Transport: JSON over HTTPS. The machine-readable contract is
`contracts/openapi.yaml`.

## Conventions

- **Authentication**: `Authorization: Bearer <jwt>`. Customer routes accept Supabase
  JWTs; `/v1/admin/*` requires an operator JWT from the admin issuer.
- **Correlation**: every response includes `X-Correlation-Id`. Clients may send one via
  `X-Correlation-Id`; otherwise the server generates one.
- **Idempotency**: mutating endpoints accept `Idempotency-Key`. Usage and installation
  operations require a stable key to make retries safe.
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

## Stripe webhook receipt

`POST /v1/webhooks/stripe` verifies `Stripe-Signature` with `STRIPE_WEBHOOK_SECRET`
before parsing or writing any event. Verified events are parsed into a minimal
non-PII summary and stored once in `stripe_webhook_events` by Stripe event id. Duplicate
deliveries return `200` with `duplicate: true`.

Supported commerce events are stored with `status = "received"` for follow-up state
application. Unsupported events are acknowledged and stored as `ignored`. Subscription
mutation, audit writes, and DataForge outbox emission from the received events remain the
next Phase 5 implementation slice.
