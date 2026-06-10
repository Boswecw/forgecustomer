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
3. Customer/admin extractors parse `Authorization: Bearer <jwt>`.
4. The matching JWT validator checks signature, issuer, audience, and expiry.
5. New customers call `POST /v1/account/provision`; this validates the Supabase JWT and
   creates or returns the ForgeCustomer business customer row for the token subject.
6. Customer requests resolve `auth_user_id` to a ForgeCustomer business customer row.
7. `CustomerContext::require_active()` fails closed for missing profiles or suspended
   customers.
8. Handlers call repositories/services and return either JSON success or the shared error
   contract.

### Route implementation status

Public routes and auth boundaries are active. Many DB-backed mutations remain pending and
return `NOT_IMPLEMENTED` after auth succeeds. Any new endpoint should follow the same
pattern until its transaction, audit write, outbox behavior, and tests are complete.

### Background worker

The outbox worker polls pending events on a fixed interval and publishes through the
DataForge client. Retry backoff is deterministic and dead-letters after a fixed maximum
attempt count. Event publishing must remain asynchronous to the customer transaction.
