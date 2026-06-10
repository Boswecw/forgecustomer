## 10. Verification and Status

The current proof layer is a mix of Rust tests, migration validation, contract linting,
schema parsing, secret scanning, and dependency audit.

### Local verification

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
bash doc/system/BUILD.sh
```

The API uses SQLx runtime query APIs, so Rust build/test does not require a live database.
Migration and RLS validation require PostgreSQL or the CI migration job.

### CI gates

| Job | Checks |
| --- | --- |
| `rust` | `cargo fmt --all --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all` |
| `migrations` | Postgres 16 migration apply, deterministic reapply, seed idempotency, RLS coverage, append-only ledger update rejection |
| `contracts` | Redocly OpenAPI lint, JSON schema parse checks |
| `secret-scan` | Gitleaks over repo history |
| `audit` | `cargo audit` |

### Tests covered today

- JWT validator accepts valid tokens and rejects expired, wrong-audience, wrong-issuer,
  bad-signature, and unconfigured-secret cases.
- Bearer header parsing.
- Checkout request validation and Stripe Checkout Session form construction.
- Stripe checkout/subscription/invoice event extraction for webhook processing.
- Account provisioning input validation and customer-auth boundary.
- Installation registration validation: install key shape, Ed25519 public-key decode and
  fingerprint stability, app version, and device label rules.
- License sync transitions: issuance on cloud-granting status, past-due grace, suspension,
  expiry, reactivation, and that revoked licenses never auto-lift.
- Stripe webhook signature, parsing, missing/bad signature, and malformed signed-envelope
  rejection behavior.
- Customer token cannot access admin route.
- Unauthenticated admin route is rejected.
- All licensing routes (listings, registration, and parameterized
  activate/heartbeat/deactivate) and parameterized admin routes fail closed without auth.
- Valid operator token reaches pending admin handler and returns `NOT_IMPLEMENTED`.
- Public health route requires no token.
- Error responses include the shared error contract and correlation ID.
- Domain/service unit tests cover subscription status normalization, entitlement
  precedence, signing and verification, key-ring behavior, quota decisions, device limit
  checks, offline lease validity, redaction, Stripe webhook verification, DataForge
  publish hygiene, and outbox backoff.

### Known implementation gaps

These are intentional MVP gaps and should not be hidden by documentation:

- Entitlement snapshot assembly and offline lease issuance.
- Usage reserve/commit/release/current route wiring.
- Admin handler implementations (including license revocation).
- Deletion workflow endpoints.
- Remaining outbox emit sites from the still-pending mutations.
- End-to-end suites with live or mocked Stripe/Supabase/DataForge flows (including
  DB-backed proofs for device-limit, revocation, and registration idempotency paths).

### Release standard

A feature is not releasable until it has:

- Route/service/repository implementation.
- Transactional behavior for state, audit, and outbox where relevant.
- Auth and RLS boundary tests.
- Idempotency or replay tests for retried operations.
- Contract/doc updates in the same change.
- A passing local or CI proof appropriate to the feature.
