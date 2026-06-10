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
| 5 | Commerce & Stripe | 🟡 | schema + webhook signature verification, parsing, idempotent receipt, and normalization logic; checkout + subscription state application pending |
| 6 | Licensing | 🟡 | schema + device-limit/lease logic; install/activate endpoints pending |
| 7 | Entitlements | 🟡 | precedence eval + Ed25519 signing/verify + keys endpoint live; snapshot assembly pending |
| 8 | Usage & quotas | 🟡 | schema + quota decision/rebuild logic; reserve/commit endpoints pending |
| 9 | Commercial audit | 🟡 | append-only table + enforcement; mutation wiring pending |
| 10 | Admin API | 🟡 | routes + operator-auth boundary enforced; handlers pending |
| 11 | DataForge outbox | 🟡 | outbox table + worker (backoff/dead-letter) + sanitizing client; emit sites pending |
| 12 | Privacy & deletion | 🟡 | schema + workflow doc; endpoints pending |
| 18 | RLS | ✅ | enabled on all tables; read-own + public-catalog policies; CI asserts coverage |
| 19 | Security hardening | 🟡 | JWT issuer/audience/exp, constant-time webhook verify, key rotation, security headers; rate limiting + cargo-audit in CI |
| 21 | Testing | 🟡 | 51 unit + 10 security integration tests; DB-backed e2e suites deferred (see `tests/README.md`) |
| 22 | Documentation | ✅ | all docs present; kept in-sync with code |
| 23 | CI | ✅ | fmt, clippy -D warnings, test, migration determinism, RLS assert, OpenAPI lint, secret scan, audit |

## MVP cut line — remaining to ship AuthorForge

The schema, auth, crypto, and pure business logic for every MVP item exist and are tested.
What remains is the **DB-backed endpoint wiring** (handlers currently return
`NOT_IMPLEMENTED` while enforcing the correct auth boundary):

1. Checkout session creation + received Stripe event application → subscription
   normalization (Phase 5), each writing audit + outbox in one transaction.
2. Installation register/activate/heartbeat/deactivate with device-limit enforcement
   (Phase 6).
3. Entitlement snapshot assembly from plan/grants/overrides → sign → return (Phase 7);
   offline-lease issuance.
4. Usage check/reserve/commit/release with idempotency (Phase 8).
5. Admin handlers (suspend/restore/resync/issue/revoke/override/adjust/audit) (Phase 10).
6. Outbox emit sites + deletion workflow endpoints (Phases 11–12).

Each lands with its endpoint tests and a docs update, per the execution rules.
