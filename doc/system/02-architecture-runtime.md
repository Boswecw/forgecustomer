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
