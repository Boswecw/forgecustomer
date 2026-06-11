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
