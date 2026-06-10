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
| `POST /v1/webhooks/stripe` | implemented receipt layer | Verifies Stripe signature, parses a minimal event envelope, stores/dedupes by Stripe event id, and explicitly ignores unsupported events. Subscription mutation remains pending. |

### Customer routes

Customer routes require a valid Supabase JWT and an active ForgeCustomer customer profile.
The exception is `POST /v1/account/provision`, which requires a valid Supabase JWT but
does not require an existing profile because it is the controlled profile-creation flow.
Current route surface:

- `GET /v1/account`
- `POST /v1/account/provision`
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
idempotently and writes the initial status-history receipt for newly-created profiles.
`GET /v1/account` returns the resolved customer/auth identifiers today. The remaining
DB-backed customer handlers currently return `NOT_IMPLEMENTED` after auth and active
customer checks pass.

### Admin routes

Admin routes require an operator JWT from `ADMIN_JWT_ISSUER` and `ADMIN_JWT_AUDIENCE`.
A valid customer token must never satisfy an admin extractor.

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

Admin handlers are intentionally pending. Each eventual admin mutation must require a
reason, write commercial audit, preserve append-only ledgers, and use compensating events
for corrections.

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

### Idempotency and correlation

- Every response includes `x-correlation-id`.
- Clients may provide `x-correlation-id`; otherwise the service generates `corr_<uuid>`.
- Mutating endpoints that can be retried should accept `Idempotency-Key`.
- Usage, installation, Stripe webhook, and outbox delivery paths must treat replay as
  expected behavior, not as an exceptional production incident.
