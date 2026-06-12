# Tests

ForgeCustomer's test strategy spans three layers.

## 1. Runnable now (in CI)

| Suite | Location | What it covers |
| ----- | -------- | -------------- |
| Unit (domain/services/integrations) | `api/src/**/tests` (`cargo test`) | customer provisioning validation, checkout request validation, installation registration validation (install key, Ed25519 device key + fingerprint, app version, label), admin input validation (reason/device-limit/adjustment/period/override-value/release/artifact bounds), usage rules (amount bounds, cadence period keys, quota-key candidates, threshold-crossing detection), deletion state machine (linear forward path; cancel/reject/execute gates), Stripe Checkout form construction, subscription normalization, license-sync transitions (issue/suspend/expire/reactivate; revoked never auto-lifts), entitlement precedence + check-key validation, signed-snapshot sign/verify + key rotation, signed-lease canonical bytes + sign/verify/tamper, quota decisions, device-limit & offline-lease rules, outbox redaction, Stripe webhook signature verification (valid/tampered/wrong-secret/replay/malformed), Stripe event envelope parsing/extraction, rate limiting, correlation-id hardening, outbox backoff |
| Security integration | `api/tests/security.rs` | unauthenticated routes fail closed (including all licensing, entitlement, usage, deletion, and subscription routes and parameterized installation/admin routes); entitlement keys and public release distribution stay public; **customer token cannot access admin route**; valid operator token clears admin auth in front of data access; **admin mutations require the `admin` role** (support role 403s on every mutation incl. release/artifact registration and deletion advance/reject/execute, reads pass); admin reason/shape validation rejects before DB writes; usage adjustments and release registration require idempotency keys; account provisioning auth/input boundary; Stripe webhook fail-closed boundary; body-size, timeout, rate-limit, and hostile-correlation-id guards; error contract shape |
| Migration + RLS | `.github/workflows/ci.yml` (`migrations` job) | clean apply, **deterministic reruns**, idempotent seed, **RLS enabled on every table**, AuthorForge update eligibility SQL matrix, customer RLS write-denial matrix, append-only ledger rejects UPDATE |
| Release package smoke | `.github/workflows/ci.yml` (`release-pipeline-smoke` job) | creates immutable bootstrap/updater fixture packages, verifies checksum/size evidence, publishes release/artifact metadata into PostgreSQL, starts the real API, and proves the public bootstrap lookup returns the expected artifact URL |
| Update campaign HTTP smoke | `.github/workflows/ci.yml` (`update-campaign-http-smoke` job) | seeds a customer/fleet/installation/release/campaign fixture, mints a customer JWT, starts the real API, and proves Tauri 200/204 response shape, same-version/same-build skips, minimum supported/updater version gates, and deterministic rollout bucket behavior |

Run locally:

```bash
cargo test --all          # unit + security integration
bash scripts/release_pipeline_smoke.sh  # after migrations + seed are applied to DB_NAME/PSQL
bash scripts/update_campaign_http_smoke.sh  # after migrations + seed are applied to DB_NAME/PSQL
# migration/RLS checks: see the `migrations` job in CI, or apply supabase/migrations/*.sql
```

## 2. Mandatory security checklist (status)

From the plan — ✅ covered today, 🔜 pending DB-backed flow wiring:

- ✅ Customer cannot call admin route
- ✅ Account provisioning requires a valid customer JWT and rejects invalid profile input
- ✅ Checkout request validation rejects malformed plan keys and redirect URLs
- ✅ Invalid / expired / wrong-audience / wrong-issuer / bad-signature JWT rejected
- ✅ Webhook with invalid signature rejected; duplicate-by-timestamp replay rejected
- ✅ Webhook receipt rejects missing/bad signatures and malformed signed event envelopes
- ✅ Forged entitlement snapshot fails verification
- ✅ Cross-customer reads/writes blocked by RLS (policies asserted present in CI)
- ✅ Customer cannot create license / grant entitlement / alter usage total (RLS denies
  even when a customer role is granted broad table privileges; licenses remain API-owned
  and webhook/admin driven)
- ✅ Duplicate Stripe webhook events are deduped before state application
- 🔜 Revoked installation denied, and duplicate usage events processed once (both
  implemented and proven against a live local PostgreSQL; CI-runnable DB-backed
  integration tests pending)

## 3. Deferred (require live or mocked Stripe / Supabase)

The `tests/integration`, `tests/stripe`, `tests/licensing`, and `tests/entitlement`
directories are reserved for end-to-end suites that drive real flows (Checkout → webhook →
subscription → entitlement; installation registration → activation; usage reserve/commit;
outbox publishing; deletion workflow). These land alongside the corresponding endpoint
implementations or dedicated DB-backed proof slices (see `docs/` and the MVP cut line).
The failure-injection matrix (Stripe / Supabase / DataForge unavailable, worker crash
after commit, out-of-order webhooks, reservation expiry, key rotation, mid-request
suspension) is specified there.
