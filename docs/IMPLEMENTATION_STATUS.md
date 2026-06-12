# IMPLEMENTATION_STATUS.md

Tracks progress against the ForgeCustomer plan. This is a living document; update it in the
same change as implementation.

## Legend
✅ done & tested  ·  🟡 foundation in place, wiring pending  ·  ⬜ not started

## Phases

| Phase | Area | Status | Notes |
| ----- | ---- | ------ | ----- |
| 0 | Architecture lock (docs) | ✅ | SYSTEM, DATA_AUTHORITY, SECURITY + domain docs |
| 1 | Supabase foundation | ✅ | 11 migrations; clean + deterministic apply; idempotent seed |
| 2 | Customer identity model | ✅ | tables + RLS done; API-owned profile provisioning live and idempotent |
| 3 | Product catalog | ✅ | versioned plans/features/quotas; AuthorForge seeded; `/v1/products`,`/v1/plans` live |
| 4 | API foundation | ✅ | health/ready/version, middleware, error contract, JWT auth, context extractors |
| 5 | Commerce & Stripe | 🟡 | checkout creation + webhook signature verification, idempotent processing, subscription projection, invoice reference recording, license sync, audit, and sanitized outbox emission live; DB-backed e2e suites pending |
| 6 | Licensing | ✅ | install/activate/heartbeat/deactivate + device/license listings live with device-limit + revocation enforcement; registration now assigns default fleet + update metadata; subscription-linked license issuance/sync live |
| 7 | Entitlements | ✅ | snapshot assembly/sign/store/return, feature+quota check, and offline-lease issuance live; keys endpoint + precedence eval + Ed25519 signing/verify |
| 8 | Usage & quotas | ✅ | check/reserve/commit/release/current live: idempotent, lock-serialized quota gating, decision history, reservation expiry (lazy + sweeper), threshold + commit-failed outbox events |
| 9 | Commercial audit | ✅ | append-only table + enforcement; Stripe, licensing, lease, and all admin mutation writes live (operator actor + reason); deletion-workflow writes land with Phase 12 |
| 10 | Admin API | ✅ | Forge Command surface live: customers, fleets, releases, campaigns, holds, update failures, artifact quarantine, suspend/restore, Stripe resync, license issue/revoke, entitlement override, usage adjust, audit read; mutations require the `admin` role + reason + idempotency where retryable |
| 11 | DataForge outbox | ✅ | outbox table + worker (backoff/dead-letter) + sanitizing client; every contract emit site live (customer_created/anonymized, subscription_changed, installation_registered, license_activated/revoked, customer_suspended/restored, quota_threshold_reached, usage_commit_failed) |
| 12 | Privacy & deletion | ✅ | deletion workflow live end to end: customer request/cancel, operator advance/reject/execute, non-destructive cooling-off, anonymization transaction with receipt + customer_anonymized emit; anonymized accounts fail closed |
| 13 | Fleet/update foundation | ✅ | default fleet/backfill/RLS, release/artifact/campaign/hold/outcome tables, release/artifact registration, public bootstrap lookup, admin control API, deterministic rollout, Tauri update lookup, bounded update-event receipts, CI DB-backed eligibility matrix, and release package publication smoke proof live |
| 18 | RLS | ✅ | enabled on all tables; read-own + public-catalog policies; CI asserts coverage |
| 19 | Security hardening | ✅ | JWT issuer/audience/exp, constant-time webhook verify, key rotation, security headers, request timeout + body-size cap, per-client rate limiting, hardened correlation ids, cargo-audit in CI |
| 21 | Testing | 🟡 | 104 unit + 30 security integration tests; CI-runnable DB-backed e2e suites deferred (see `tests/README.md`) |
| 22 | Documentation | ✅ | all docs present; kept in-sync with code |
| 23 | CI | ✅ | fmt, clippy -D warnings, test, migration determinism, RLS assert, OpenAPI lint, secret scan, audit |

## MVP cut line — remaining to ship AuthorForge

**Every MVP endpoint is implemented** — no handler returns `NOT_IMPLEMENTED`:

1. ✅ Installation register/activate/heartbeat/deactivate with device-limit enforcement,
   plus subscription-linked license issuance/sync (Phase 6).
2. ✅ Entitlement snapshot assembly from plan/grants/overrides → sign → store → return,
   feature/quota check, and offline-lease issuance (Phase 7).
3. ✅ Usage check/reserve/commit/release/current with idempotency, reservation expiry,
   and threshold events (Phase 8).
4. ✅ Admin handlers (suspend/restore/resync/issue/revoke/override/adjust/audit),
   consumed by Forge Command with role-gated mutations (Phase 10).
5. ✅ Deletion workflow (customer request/cancel; operator advance/reject/execute with
   anonymization receipt) + every contract outbox emit site incl. `customer_anonymized`
   (Phases 11–12), plus the subscription summary endpoint.
6. ✅ AuthorForge fleet/update foundation: default fleet assignment, release/campaign
   admin control, deterministic rollout, Tauri update lookup, and bounded update-event
   receipts are implemented. Release-pipeline metadata/artifact registration and public
   generic installer lookup are implemented. A CI DB-backed eligibility matrix covers
   held fleets, campaign holds, paused/revoked campaigns, unpublished releases,
   quarantined artifacts, updater-vs-bootstrap artifact role separation, cross-customer
   lookups, and duplicate update-event receipts. The release-pipeline smoke job creates
   immutable bootstrap/updater fixture packages, verifies checksum/size evidence,
   publishes release metadata, and proves the public bootstrap lookup returns the
   expected artifact URL.
7. Remaining: CI-runnable DB-backed end-to-end suites for Stripe/Supabase/DataForge
   happy paths and failures (the live local suites — 174 checks across Phases 6/7/8/10/12
   — are the blueprint; see `tests/README.md`).

Each lands with its endpoint tests and a docs update, per the execution rules.
