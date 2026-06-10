# Tests

ForgeCustomer's test strategy spans three layers.

## 1. Runnable now (in CI)

| Suite | Location | What it covers |
| ----- | -------- | -------------- |
| Unit (domain/services/integrations) | `api/src/**/tests` (`cargo test`) | customer provisioning validation, subscription normalization, entitlement precedence, signed-snapshot sign/verify + key rotation, quota decisions, device-limit & offline-lease rules, outbox redaction, Stripe webhook signature verification (valid/tampered/wrong-secret/replay/malformed), Stripe event envelope parsing, outbox backoff |
| Security integration | `api/tests/security.rs` | unauthenticated routes fail closed; **customer token cannot access admin route**; valid operator token clears admin auth; account provisioning auth/input boundary; Stripe webhook fail-closed boundary; error contract shape |
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
- ✅ Invalid / expired / wrong-audience / wrong-issuer / bad-signature JWT rejected
- ✅ Webhook with invalid signature rejected; duplicate-by-timestamp replay rejected
- ✅ Webhook receipt rejects missing/bad signatures and malformed signed event envelopes
- ✅ Forged entitlement snapshot fails verification
- ✅ Cross-customer reads/writes blocked by RLS (policies asserted present in CI)
- 🔜 Customer cannot create license / grant entitlement / alter usage total (RLS denies;
  end-to-end test pending the write endpoints)
- 🔜 Revoked installation denied; duplicate Stripe/usage event processed once (logic +
  schema present; integration test pending endpoint wiring)

## 3. Deferred (require live or mocked Stripe / Supabase)

The `tests/integration`, `tests/stripe`, `tests/licensing`, and `tests/entitlement`
directories are reserved for end-to-end suites that drive real flows (Checkout → webhook →
subscription → entitlement; installation registration → activation; usage reserve/commit;
outbox publishing; deletion workflow). These land alongside the corresponding endpoint
implementations (see `docs/` and the MVP cut line). The failure-injection matrix (Stripe /
Supabase / DataForge unavailable, worker crash after commit, out-of-order webhooks,
reservation expiry, key rotation, mid-request suspension) is specified there.
