# IMPLEMENTATION_STATUS.md

Tracks progress against the ForgeCustomer plan. This is a living document; update it in the
same change as implementation.

## Legend
✅ done & tested  ·  🟡 foundation in place, wiring pending  ·  ⬜ not started

## Phases

| Phase | Area | Status | Notes |
| ----- | ---- | ------ | ----- |
| 0 | Architecture lock (docs) | ✅ | SYSTEM, DATA_AUTHORITY, SECURITY + domain docs |
| 1 | Supabase foundation | ✅ | 10 migrations; clean + deterministic apply; idempotent seed |
| 2 | Customer identity model | ✅ | tables + RLS done; API-owned profile provisioning live and idempotent |
| 3 | Product catalog | ✅ | versioned plans/features/quotas; AuthorForge seeded; `/v1/products`,`/v1/plans` live |
| 4 | API foundation | ✅ | health/ready/version, middleware, error contract, JWT auth, context extractors |
| 5 | Commerce & Stripe | 🟡 | checkout creation + webhook signature verification, idempotent processing, subscription projection, invoice reference recording, license sync, audit, and sanitized outbox emission live; DB-backed e2e suites pending |
| 6 | Licensing | ✅ | install/activate/heartbeat/deactivate + device/license listings live with device-limit + revocation enforcement; subscription-linked license issuance/sync live; offline-lease endpoint lands with Phase 7 |
| 7 | Entitlements | ✅ | snapshot assembly/sign/store/return, feature+quota check, and offline-lease issuance live; keys endpoint + precedence eval + Ed25519 signing/verify |
| 8 | Usage & quotas | ✅ | check/reserve/commit/release/current live: idempotent, lock-serialized quota gating, decision history, reservation expiry (lazy + sweeper), threshold + commit-failed outbox events |
| 9 | Commercial audit | ✅ | append-only table + enforcement; Stripe, licensing, lease, and all admin mutation writes live (operator actor + reason); deletion-workflow writes land with Phase 12 |
| 10 | Admin API | ✅ | Forge Command surface live: customers list, suspend/restore, Stripe resync, license issue/revoke, entitlement override, usage adjust, audit read; mutations require the `admin` role + reason |
| 11 | DataForge outbox | 🟡 | outbox table + worker (backoff/dead-letter) + sanitizing client; all contract emit sites live (customer_created, subscription_changed, installation_registered, license_activated, license_revoked, customer_suspended, customer_restored, quota_threshold_reached, usage_commit_failed) except customer_anonymized (Phase 12) |
| 12 | Privacy & deletion | 🟡 | schema + workflow doc; endpoints pending |
| 18 | RLS | ✅ | enabled on all tables; read-own + public-catalog policies; CI asserts coverage |
| 19 | Security hardening | 🟡 | JWT issuer/audience/exp, constant-time webhook verify, key rotation, security headers; rate limiting + cargo-audit in CI |
| 21 | Testing | 🟡 | 82 unit + 19 security integration tests; DB-backed e2e suites deferred (see `tests/README.md`) |
| 22 | Documentation | ✅ | all docs present; kept in-sync with code |
| 23 | CI | ✅ | fmt, clippy -D warnings, test, migration determinism, RLS assert, OpenAPI lint, secret scan, audit |

## MVP cut line — remaining to ship AuthorForge

The schema, auth, crypto, and pure business logic for every MVP item exist and are tested.
What remains is the **DB-backed endpoint wiring** (handlers currently return
`NOT_IMPLEMENTED` while enforcing the correct auth boundary):

1. ✅ Installation register/activate/heartbeat/deactivate with device-limit enforcement,
   plus subscription-linked license issuance/sync (Phase 6).
2. ✅ Entitlement snapshot assembly from plan/grants/overrides → sign → store → return,
   feature/quota check, and offline-lease issuance (Phase 7).
3. ✅ Usage check/reserve/commit/release/current with idempotency, reservation expiry,
   and threshold events (Phase 8).
4. ✅ Admin handlers (suspend/restore/resync/issue/revoke/override/adjust/audit),
   consumed by Forge Command with role-gated mutations (Phase 10).
5. Deletion workflow endpoints + the `customer_anonymized` outbox emit (Phases 11–12);
   every other contract emit site is live.
6. DB-backed end-to-end suites for Stripe/Supabase/DataForge happy paths and failures.

Each lands with its endpoint tests and a docs update, per the execution rules.
