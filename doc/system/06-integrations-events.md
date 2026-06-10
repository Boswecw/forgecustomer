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
projection, invoice references, audit writes, and sanitized subscription outbox emission
exist. Entitlement snapshot assembly from those projected rows remains a later phase.

### DataForge outbox

DataForge receives sanitized operational/commercial evidence through `outbox_events`.
DataForge is a sink, not a source of truth.

Outbox behavior:

- Customer transaction writes state, audit, and outbox rows in one database transaction.
- Background worker publishes pending rows to DataForge.
- DataForge failures do not roll back customer transactions.
- Retry uses deterministic backoff and eventually dead-letters exhausted events.
- Delivery keys must make repeated publishes idempotent downstream.

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
- `events/outbox-event-v1.schema.json` for DataForge outbox delivery envelopes.

CI validates OpenAPI with Redocly and checks JSON schema files parse.
