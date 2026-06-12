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
- Entitlement check-key validation and signed-lease canonical bytes (signature excluded,
  stable, sign/verify/tamper roundtrip).
- Entitlement snapshot, check, and offline-lease routes fail closed without auth; the
  keys endpoint stays public.
- Admin input validation: reason bounds, device-limit bounds, adjustment amount
  (finite/non-zero/bounded), period-key shape and window, typed override values.
- Fleet/update admin input validation: fleet/campaign slugs, release channels, update
  rings, rollout percentage, release/artifact registration metadata, reason, and
  idempotency-key requirements.
- Admin role boundary: operator tokens without the `admin` role are rejected (403) on
  every mutation; reads pass; reason validation rejects before any database write; usage
  adjustments without an idempotency key are rejected.
- Usage domain rules: amount bounds, cadence period keys, quota-key candidate order, and
  threshold-crossing detection (fires exactly on crossing, never re-fires, never for
  unlimited/zero limits).
- All five usage routes fail closed without auth.
- Deletion state machine: linear forward path, cancel/reject stop at processing,
  execution only from processing; deletion and subscription routes fail closed without
  auth and the admin deletion mutations are role-gated.
- Stripe webhook signature, parsing, missing/bad signature, and malformed signed-envelope
  rejection behavior.
- Customer token cannot access admin route.
- Unauthenticated admin route is rejected.
- All licensing/update routes (listings, registration, update lookup, update events, and
  parameterized activate/heartbeat/deactivate/update-events) and parameterized admin
  routes fail closed without auth.
- Public release distribution routes require no token and reach the data layer without
  accepting customer, fleet, or personalized artifact input.
- The CI migration job runs a DB-backed AuthorForge update eligibility matrix covering
  held fleets, campaign holds, paused/revoked campaigns, unpublished releases,
  quarantined artifacts, updater-vs-bootstrap artifact role separation, cross-customer
  installation lookups, and duplicate update-event receipt idempotency.
- The CI release-pipeline smoke job creates immutable bootstrap/updater fixture
  packages, verifies checksum and size evidence, publishes release/artifact metadata
  into PostgreSQL, starts the real API, and proves the public bootstrap lookup returns
  the expected artifact URL.
- Valid operator token reaches admin reads and then fails on the unreachable test
  database, proving auth clears before data access.
- Public health route requires no token.
- Error responses include the shared error contract and correlation ID.
- Domain/service unit tests cover subscription status normalization, entitlement
  precedence, signing and verification, key-ring behavior, quota decisions, device limit
  checks, offline lease validity, fleet/update validation, deterministic HMAC rollout
  vectors, redaction, Stripe webhook verification, DataForge publish hygiene, and outbox
  backoff.

### Known implementation gaps

These are intentional MVP gaps and should not be hidden by documentation:

- End-to-end suites with live or mocked Stripe/Supabase/DataForge flows in CI. The live
  local verification suites (174 checks across licensing, entitlements, usage, admin,
  and deletion against PostgreSQL 16 with a mocked Stripe API) are the blueprint.
- Broader end-to-end update campaign tests driven through HTTP plus a live PostgreSQL
  fixture, including version-minimum and deterministic rollout bucket scenarios.

### Release standard

A feature is not releasable until it has:

- Route/service/repository implementation.
- Transactional behavior for state, audit, and outbox where relevant.
- Auth and RLS boundary tests.
- Idempotency or replay tests for retried operations.
- Contract/doc updates in the same change.
- A passing local or CI proof appropriate to the feature.
