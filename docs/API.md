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
| `/v1/products/{product}/releases` | public published release/download lookup | none      |
| `/v1/subscriptions`    | own subscription summary                            | customer  |
| `/v1/licenses`         | own licenses                                        | customer  |
| `/v1/installations`    | register / list / activate / heartbeat / deactivate | customer  |
| `/v1/updates/authorforge` | Tauri-compatible update lookup                  | customer  |
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

## Public release distribution

- `GET /v1/products/{product_key}/releases/latest?channel=stable` returns the latest
  published release metadata only. Draft, validated-but-unpublished, blocked, and retired
  releases are not exposed.
- `GET /v1/products/{product_key}/downloads?platform=linux&arch=x86_64&channel=stable`
  resolves a validated `bootstrap` artifact for the latest published release. The
  installer is generic: no customer id, fleet id, or personalized binary is embedded in
  the response. Relative artifact keys use `RELEASE_ARTIFACT_BASE_URL`; absolute artifact
  URLs are returned as-is.

## Account provisioning

`POST /v1/account/provision` is the controlled API-owned profile creation flow for a
Supabase-authenticated user. It validates the customer JWT but does **not** require an
existing ForgeCustomer profile. The server creates one business customer row for the
 token subject, creates/returns the customer's default AuthorForge fleet, writes the
initial status history receipt, projects the trusted Supabase email claim when present,
and returns the existing row on repeat calls.

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

## Subscriptions and account deletion

- `GET /v1/subscriptions` — the caller's subscription projections (product/plan keys,
  status, `grants_cloud`, period end, cancel-at-period-end).
- `POST /v1/account/deletion-request` — opens a deletion request (idempotent while one
  is open); `GET` reads the latest; `POST …/cancel` cancels cleanly until processing
  begins (`409` afterwards). See `docs/PRIVACY.md` for the operator-driven workflow
  (`/v1/admin/deletion-requests*`), the non-destructive cooling-off, the execution
  transaction, and the retention exceptions. Anonymized accounts fail closed at the
  auth boundary.

## Licensing: installations, devices, licenses

See `docs/LICENSING.md` for the full rules. Summary of the live endpoints:

- `POST /v1/installations` registers an installed application instance, idempotent on the
  client-supplied `install_key` (8–120 chars of `[A-Za-z0-9._:-]`). The server assigns
  the customer's default fleet and accepts bounded update metadata (`build_id`,
  `platform`, `architecture`, `package_format`, `updater_version`). An optional
  `device_public_key` (base64 32-byte Ed25519 public key) registers the device identity;
  the private key never leaves the client. Re-registering a deactivated installation
  reactivates the installation record; license slots are only consumed by activation.
  First registration queues a sanitized `installation_registered` outbox event including
  the server-resolved `fleet_id`.
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
- `GET /v1/updates/authorforge/{target}/{arch}/{current_version}` is the dynamic Tauri
  updater endpoint. It requires `X-Forge-Installation-ID` and optional build/updater
  headers, resolves the fleet only from the owned installation, and returns `204` unless
  every campaign gate passes: active fleet/application, published release, validated
  artifact, matching channel/ring/platform/package, no hold, version gates, and the
  server-side HMAC rollout bucket. An eligible update returns exactly
  `{ version, url, signature, notes, pub_date }`.
- `POST /v1/installations/{id}/update-events` records minimal update outcomes with the
  event UUID in `Idempotency-Key`. Unknown body fields are rejected; raw diagnostics,
  paths, hostnames, logs, and arbitrary client strings are not accepted.

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

## Usage: check, reserve, commit, release, current

See `docs/USAGE.md` for the full rules. Summary of the live endpoints:

- `POST /v1/usage/check` — advisory, read-only quota check for one meter.
- `POST /v1/usage/reserve` — holds units against the quota (requires `Idempotency-Key`;
  replays return the original reservation). Quota math runs under a per-(customer,
  meter, period) lock; over-quota requests answer `402 QUOTA_EXCEEDED` with the
  explainable decision in the details, and every decision lands in `quota_decisions`.
  Reservations expire after `USAGE_RESERVATION_TTL_SECS` (lazily and via a background
  sweeper), freeing their hold.
- `POST /v1/usage/commit` — appends to the append-only `usage_events` ledger (requires
  `Idempotency-Key`; replays do not double-charge). Either converts a pending
  reservation (charging the reservation's period; expired/terminal reservations `409`)
  or directly charges `meter_key`+`amount`, quota-gated at commit time. Threshold
  crossings queue `quota_threshold_reached` outbox events; denied direct commits queue
  `usage_commit_failed`.
- `POST /v1/usage/release` — releases an unused reservation, idempotently.
- `GET /v1/usage/current` — per-meter current-period totals with limits and remaining
  quota from the assembled entitlements.

## Admin API (Forge Command)

The `/v1/admin/*` surface is the integration point for **Forge Command**, the operator
console. Forge Command mints operator JWTs from the dedicated issuer
(`ADMIN_JWT_ISSUER`/`ADMIN_JWT_AUDIENCE`) and works exclusively through these endpoints —
it never bypasses ForgeCustomer's mutation paths or touches the database directly.

Authorization is two-tier and fails closed:

- **Reads** (`GET /v1/admin/customers`, fleet/release/campaign/failure reads, and
  `GET /v1/admin/audit`) require any valid operator token.
- **Mutations** additionally require the `admin` role in the token's `roles` claim and a
  written `reason` (3–500 chars) that lands in the commercial audit trail with the
  operator id as the actor.

Live endpoints:

- `GET /v1/admin/customers` — lookup by exact email and/or status, paged.
- `POST /v1/admin/customers/{id}/suspend` / `restore` — idempotent status changes that
  write `customer_status_history`, audit, and the sanitized
  `customer_suspended`/`customer_restored` outbox events. Suspension fails the customer
  closed at the auth boundary (`CUSTOMER_SUSPENDED`).
- `POST /v1/admin/subscriptions/{id}/resync` — pulls current truth from the Stripe API
  (`STRIPE_API_BASE` is overridable for mocked tests), reprojects the subscription,
  syncs the linked license, and advances the event watermark so stale out-of-order
  webhooks are skipped afterwards. Queues `subscription_changed` only when the
  projection actually changed.
- `POST /v1/admin/licenses` — operator-issued license (bounded `device_limit`, optional
  expiry); subscription-linked licenses remain webhook-managed.
- `POST /v1/admin/licenses/{id}/revoke` — idempotent revocation: sets `revoked`, writes
  the explicit `license_revocations` record (blocks activation/leases; never lifted by
  subscription sync), audits, and queues the `license_revoked` outbox event.
- `POST /v1/admin/entitlements/override` — sets a typed feature/quota override
  (deactivating prior active overrides for the same key) or clears the key when the
  value is omitted.
- `POST /v1/admin/usage/adjust` — appends a signed compensating adjustment to the
  append-only usage ledger and folds it into the period total. Requires
  `Idempotency-Key`; replays return the original event without re-applying. Corrections
  are compensating events, never edits.
- `GET /v1/admin/audit` — commercial audit events, filterable by customer and event
  type, newest first.
- `GET /v1/admin/fleets`, `GET /v1/admin/fleets/{id}`,
  `POST /v1/admin/fleets/{id}/policy` — operator fleet review and policy changes
  (display name, ring, channel, beta enrollment).
- `POST /v1/admin/releases` — idempotent release-pipeline intake for draft release
  metadata, keyed by product/version/build. It requires an idempotency key and writes
  operator audit; publication remains separate.
- `POST /v1/admin/releases/{id}/artifacts` — idempotent immutable artifact registration
  for bootstrap/updater/recovery artifacts after the pipeline verifies upload, checksum,
  size, signing, and package evidence. Replays with different metadata are conflicts.
- `GET /v1/admin/releases`, `GET /v1/admin/releases/{id}`,
  `POST /v1/admin/releases/{id}/validate|publish|block` — release catalog controls.
  Validation requires at least one validated artifact; publication requires validated
  release state.
- `POST /v1/admin/update-campaigns`, `GET /v1/admin/update-campaigns/{id}`, and
  `pause|resume|revoke|rollout` mutations — campaign controls. Campaigns are created at
  `0%` rollout; rollout increases are explicit audited mutations.
- `POST /v1/admin/update-campaigns/{campaign_id}/holds` and
  `DELETE /v1/admin/update-campaigns/{campaign_id}/holds/{fleet_id}` — fleet-level
  campaign holds.
- `GET /v1/admin/update-failures` — recent failed/recovery update outcome events.
- `POST /v1/admin/release-artifacts/{id}/quarantine` — quarantine an artifact and pause
  campaigns targeting its release.
