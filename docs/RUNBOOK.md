# RUNBOOK.md — operations

## Deploy

1. Provision/select the target Supabase project (dev/staging/prod) and set its secret set.
2. Apply migrations: `supabase db push` (or `supabase db reset` for a clean dev DB).
3. Set environment variables (see `.env.example`).
4. Build & run the API: `cd api && cargo build --release && ./target/release/forgecustomer-api`.
5. Verify: `GET /v1/health` → ok, `GET /v1/ready` → 200, `GET /v1/version`.

### Render (Docker)

- The image builds from `deploy/Dockerfile` with the repo root as build context; there
  is intentionally **no root `Dockerfile`**. `render.yaml` (Blueprint) encodes this.
  For a manually created service, set **Settings → Build & Deploy → Dockerfile Path**
  to `deploy/Dockerfile` (Docker build context stays `.`), or the build fails with
  `failed to read dockerfile: open Dockerfile: no such file or directory`.
- The app binds `0.0.0.0:$PORT`; the Blueprint pins `PORT=8080` to match the image's
  `EXPOSE`. Health check path is `/v1/ready` so rollouts gate on DB reachability.
- Postgres is the Supabase project, not a Render database: point `DATABASE_URL` at
  Supabase's pooled connection string. Migrations still ship via `supabase db push`
  (step 2) — the API container never applies migrations.
- All secrets are entered in the Render dashboard (`sync: false` in the Blueprint);
  they are never committed. Use an always-on plan: free instances idle out and stall
  the outbox publisher and reservation sweeper.

## Health & readiness

- `health` = process up. `ready` = DB reachable. Load balancers should gate on `ready`.

## Stripe

- Configure the webhook endpoint to `POST /v1/webhooks/stripe` with the events listed in
  `docs/STRIPE.md`. Set `STRIPE_WEBHOOK_SECRET`.
- **Resync a subscription**: `POST /v1/admin/subscriptions/{id}/resync` re-fetches Stripe
  state and re-normalizes (idempotent). Use after suspected drift.
- Replaying a webhook is safe (dedupe by event id).

## Entitlement signing key rotation

1. Generate a new Ed25519 key; add it to the published keys endpoint as `entitlement-key-N`.
2. Keep the previous key published (overlap window) so existing snapshots still verify.
3. Switch `ENTITLEMENT_SIGNING_KEY_ID` / `ENTITLEMENT_SIGNING_PRIVATE_KEY` to the new key.
4. After max snapshot/lease lifetime + grace, retire the old key from the endpoint.

## Outbox / DataForge

- The outbox worker publishes sanitized events with retry+backoff. A DataForge outage does
  not block customer transactions (events queue in `outbox_events`).
- **Inspect failures**: query `outbox_events` where `status = 'dead_letter'`.
- **Replay**: reset `status` to `pending` (admin tooling) — delivery is idempotent.

## Usage

- **Rebuild totals** from the ledger if `usage_period_totals` is suspected stale: recompute
  per `(customer, meter, period)` from `usage_events`.
- Expired reservations are swept by a background task; freed quota returns automatically.

## Incident: suspected forged entitlement

- Verify `key_id` against published keys; check signature. Rotate the signing key if
  compromise is suspected and revoke affected leases.

## Common admin actions

| Action                  | Endpoint                                         |
| ----------------------- | ------------------------------------------------ |
| Suspend customer        | `POST /v1/admin/customers/{id}/suspend` (reason) |
| Restore customer        | `POST /v1/admin/customers/{id}/restore` (reason) |
| Issue / revoke license  | `POST /v1/admin/licenses` / `.../revoke`         |
| Override entitlement    | `POST /v1/admin/entitlements/override`           |
| Adjust usage            | `POST /v1/admin/usage/adjust` (compensating)     |
| Read audit              | `GET /v1/admin/audit`                            |

Every admin mutation requires a reason and writes a `commercial_audit_event`.
