# ENTITLEMENTS.md — entitlement evaluation & signed snapshots

## Tables (migration `0005_entitlements.sql`)

`entitlement_grants`, `entitlement_overrides`, `entitlement_snapshots`.

## Evaluation order (deterministic)

```
product defaults
  → plan version (features + quotas)
    → active subscription (gates cloud features)
      → license grants
        → promotional grants
          → admin overrides
            → suspension / revocation rules
              → final entitlement result
```

Later stages win over earlier ones, except **suspension/revocation always denies**
cloud/new-lease capabilities regardless of upstream grants. Local product access is
evaluated independently and is never revoked by commercial state.

### How layers map to data (implemented)

| Layer | Source |
| ----- | ------ |
| product defaults | active version of the product's `<product>_included` plan (baseline every customer holds) |
| plan version | the customer's current subscription: prefer cloud-granting, else most recent non-canceled (canceled contributes nothing) |
| active subscription gate | `status ∈ {active, trialing}` grants cloud; others gate `*.cloud.enabled` / `*.deep_analysis.enabled` / `*.premium.enabled` off |
| license grants | `license_grants` of active, unexpired licenses |
| promotional grants | unexpired `entitlement_grants` (feature or quota keyed) |
| admin overrides | active, unexpired `entitlement_overrides` |
| denials | suspension is enforced at the auth boundary (`CUSTOMER_SUSPENDED`); a revoked latest license forces cloud features off |

Quota limits merge in the same order (included → subscription plan → grants → overrides).
Monthly meters also surface current committed usage as `<meter>.used` (e.g.
`cloud_tokens.used`) read from `usage_period_totals` for the current `YYYY-MM` period.

## Endpoints (live)

```
GET  /v1/entitlements/current       signed snapshot for the caller's context
POST /v1/entitlements/check         advisory check for a specific feature/quota
POST /v1/entitlements/offline-lease issue a signed offline lease (if not suspended/revoked)
GET  /v1/entitlements/keys          published verification keys (versioned, public)
```

- `current` accepts `?product_key=` (default `authorforge`) or `?installation_id=` (binds
  the snapshot to an owned installation and its product). Every issued snapshot is
  recorded in `entitlement_snapshots` for audit/replay.
- `check` takes exactly one of `feature_key` / `quota_key` (plus optional `amount` for
  quota checks; 0 means "currently within quota"). It is read-only and fails closed:
  absent features and over-quota meters answer `allowed: false`. Reservation decisions
  and their `quota_decisions` history belong to the usage endpoints (Phase 8).
- `offline-lease` requires an active installation with an active activation on an
  active, unexpired license; revoked devices/licenses and explicit `license_revocations`
  rows never receive a new lease. Leases live for `OFFLINE_GRACE_DAYS` and every
  issuance writes the `license_leases` row and a `lease_issued` audit event in one
  transaction.

## Signed snapshot (`forge.entitlements.v1`)

```json
{
  "schema_version": "forge.entitlements.v1",
  "customer_id": "cust_...",
  "installation_id": "inst_...",
  "product": "authorforge",
  "issued_at": "2026-06-09T20:00:00Z",
  "expires_at": "2026-06-10T20:00:00Z",
  "features": { "cloud.enabled": true, "deep_analysis.enabled": true, "devices.max": 3 },
  "quotas": { "cloud_tokens.monthly": 1000000, "cloud_tokens.used": 125000 },
  "key_id": "entitlement-key-1",
  "signature": "..."
}
```

- Signature is **Ed25519** over the canonical JSON of the payload **excluding** the
  `signature` field. `key_id` selects the verification key.
- Schema: `contracts/entitlement-v1.schema.json`.
- The wire JSON field order matches the canonical signing order (struct field order with
  sorted feature/quota maps), so clients verify by re-serializing the received document
  with `signature` cleared. The same applies to the lease document.

## Signed offline lease (`forge.lease.v1`)

```json
{
  "schema_version": "forge.lease.v1",
  "lease_id": "…",
  "customer_id": "…",
  "license_id": "…",
  "installation_id": "…",
  "product": "authorforge",
  "issued_at": "2026-06-10T20:00:00Z",
  "expires_at": "2026-06-24T20:00:00Z",
  "key_id": "entitlement-key-1",
  "signature": "…"
}
```

Schema: `contracts/lease-v1.schema.json`. Lease validity at evaluation time (expiry,
revocation, grace) is the pure logic in `api/src/domain/license.rs::validate_lease`.

## Offline doctrine

- Local writing remains available regardless of cloud/billing state.
- Cloud features require a current or recently cached entitlement.
- An expired subscription never blocks manuscript access.
- Revocation prevents issuing **new** leases.
- Defaults (configurable): snapshot lifetime **24h** (`ENTITLEMENT_SNAPSHOT_TTL_HOURS`),
  offline grace **7–14 days** (`OFFLINE_GRACE_DAYS`, default 14).

## Exit criteria (status)

- ✅ Entitlement precedence is deterministic (pure evaluator + BTreeMap ordering).
- ✅ Signed snapshots verify; forged snapshots fail verification (proven with an
  independent Ed25519 implementation against the live API).
- ✅ A suspended customer receives no new lease (`CUSTOMER_SUSPENDED` at the boundary);
  revoked contexts are denied with `REVOKED`.
- ✅ Local-only access rules are independent from cloud availability — only
  `*.cloud.enabled` / `*.deep_analysis.enabled` / `*.premium.enabled` are gated by
  subscription state; local features and device identity are untouched.
