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

## Endpoints

```
POST /v1/usage/check     will this amount fit within quota? (no state change)
POST /v1/usage/reserve   hold N units; returns reservation id + expiry
POST /v1/usage/commit    convert a reservation (or direct charge) into a ledger event
POST /v1/usage/release   release an unused/failed reservation
GET  /v1/usage/current   current period totals + remaining quota
```

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

When period usage crosses configured thresholds (e.g. 80%, 100%), a
`quota_threshold_reached` outbox event is emitted (sanitized — no content).

## Exit criteria

- Retries do not double-charge.
- Reservation and commit behavior is transactional.
- Quota limits are enforced consistently.
- Usage totals rebuild correctly from the ledger.
- Threshold events are generated.
