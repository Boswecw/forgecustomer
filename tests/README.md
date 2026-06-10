# Tests

ForgeCustomer's test strategy spans three layers.

## 1. Runnable now (in CI)

| Suite | Location | What it covers |
| ----- | -------- | -------------- |
| Unit (domain/services/integrations) | `api/src/**/tests` (`cargo test`) | customer provisioning validation, checkout request validation, installation registration validation (install key, Ed25519 device key + fingerprint, app version, label), Stripe Checkout form construction, subscription normalization, license-sync transitions (issue/suspend/expire/reactivate; revoked never auto-lifts), entitlement precedence + check-key validation, signed-snapshot sign/verify + key rotation, signed-lease canonical bytes + sign/verify/tamper, quota decisions, device-limit & offline-lease rules, outbox redaction, Stripe webhook signature verification (valid/tampered/wrong-secret/replay/malformed), Stripe event envelope parsing/extraction, outbox backoff |
| Security integration | `api/tests/security.rs` | unauthenticated routes fail closed (including all licensing + entitlement routes and parameterized installation/admin routes); entitlement keys stay public; **customer token cannot access admin route**; valid operator token clears admin auth; account provisioning auth/input boundary; Stripe webhook fail-closed boundary; error contract shape |
| Migration + RLS | `.github/workflows/ci.yml` (`migrations` job) | clean apply, **deterministic reruns**, idempotent seed, **RLS enabled on every table**, append-only ledger rejects UPDATE |

Run locally:

```bash
cargo test --all          # unit + security integration
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
- 🔜 Customer cannot create license / grant entitlement / alter usage total (RLS denies;
  licenses are only written by webhook-driven sync server-side; end-to-end test pending)
- ✅ Duplicate Stripe webhook events are deduped before state application
- 🔜 Revoked installation denied (revocation + device-status checks implemented in the
  activation path; DB-backed integration test pending); duplicate usage event processed
  once (logic + schema present; integration test pending endpoint wiring)

## 3. Deferred (require live or mocked Stripe / Supabase)

The `tests/integration`, `tests/stripe`, `tests/licensing`, and `tests/entitlement`
directories are reserved for end-to-end suites that drive real flows (Checkout → webhook →
subscription → entitlement; installation registration → activation; usage reserve/commit;
outbox publishing; deletion workflow). These land alongside the corresponding endpoint
implementations or dedicated DB-backed proof slices (see `docs/` and the MVP cut line).
The failure-injection matrix (Stripe / Supabase / DataForge unavailable, worker crash
after commit, out-of-order webhooks, reservation expiry, key rotation, mid-request
suspension) is specified there.
