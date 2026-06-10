# USAGE.md — usage metering & quotas

## Authority model

| Table                 | Role                                              |
| --------------------- | ------------------------------------------------- |
| `usage_events`        | authoritative, **append-only** ledger             |
| `usage_period_totals` | derived optimization (rebuildable from the ledger)|
| `usage_reservations`  | in-flight holds against a quota                    |
| `quota_decisions`     | explainable decision history                       |
| `usage_meters`        | meter catalog (units, reset cadence)               |

Tables in migration `0006_usage.sql`.

## Endpoints (live)

```
POST /v1/usage/check     will this amount fit within quota? (no state change)
POST /v1/usage/reserve   hold N units; returns reservation id + expiry
POST /v1/usage/commit    convert a reservation (or direct charge) into a ledger event
POST /v1/usage/release   release an unused/failed reservation
GET  /v1/usage/current   current period totals + remaining quota
```

## Implemented semantics

- **Limits** come from the assembled entitlement quotas (included plan → subscription
  plan → grants → admin overrides): the cadence-qualified key (`cloud_tokens.monthly`)
  wins over the bare meter key; a meter with no quota row is uncapped.
- **Period keys** by meter cadence: `YYYY-MM` (monthly), `YYYY-MM-DD` (daily), `all`
  (never).
- **Locking**: quota math runs under a `(customer, meter, period)` totals-row lock, so
  concurrent reserves/commits serialize and cannot oversubscribe.
- **Idempotency**: reservations dedupe on `(customer, Idempotency-Key)` in
  `usage_reservations`; commits dedupe on the same pair in `usage_events`. Replays
  return the original row. Denied reserves hold nothing and re-evaluate on retry.
- **Reservation expiry** (`USAGE_RESERVATION_TTL_SECS`, default 900): stale pending
  holds are expired lazily inside the reserve/commit lock for the customer touched, and
  a background sweeper (`workers::usage`, 30s interval) reclaims the rest. Committing an
  expired reservation fails closed (`409`) and frees its hold.
- **Direct commits** (no reservation) are quota-gated at commit time; denials record a
  `quota_decisions` row and queue a sanitized `usage_commit_failed` outbox event.
- **Decisions**: every reserve and direct-commit decision (allow and deny) is recorded
  in `quota_decisions` with limit/used/reserved/reason and the request correlation id.
  `check` is advisory and records nothing.

## Reserve → commit lifecycle

```
reserve(amount, idem_key) → reservation(pending, expires_at)
  → on success: commit(reservation) → usage_event (append) + totals updated  [single tx]
  → on failure: release(reservation) → reservation(released)
  → on expiry:  reservation auto-expires (background sweep), quota freed
```

## Rules

- Every event carries a unique **idempotency key**; retries do not double-charge.
- Usage events are never silently edited; corrections are **compensating events**.
- Totals can be fully rebuilt from the ledger.
- Reservation expiration is supported; failed executions release reservations.
- Meter units are explicit (e.g. tokens, runs, requests, bytes).
- Reserve+commit is transactional; quotas are enforced consistently and recorded in
  `quota_decisions` for explainability.

## Example meters

`cloud_tokens`, `deep_analysis_runs`, `premium_model_requests`, `cloud_storage_bytes`.

## Threshold events

When a commit crosses a configured threshold (`USAGE_THRESHOLD_PERCENTS`, default
`80,100`), a sanitized `quota_threshold_reached` outbox event is queued in the same
transaction. The delivery key
`quota_threshold_reached:{customer}:{meter}:{period}:{pct}` makes each threshold fire at
most once per customer/meter/period.

## Exit criteria (status)

- ✅ Retries do not double-charge (idempotency proven live for reserve and commit).
- ✅ Reservation and commit behavior is transactional (ledger + totals + decision +
  outbox in one tx).
- ✅ Quota limits are enforced consistently (reserve and direct commit share the same
  locked decision path).
- ✅ Usage totals rebuild correctly from the ledger (verified live: Σ events = totals).
- ✅ Threshold events are generated exactly on crossing, once per period.
