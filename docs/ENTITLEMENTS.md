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

## Endpoints

```
GET  /v1/entitlements/current       signed snapshot for the caller's context
POST /v1/entitlements/check         boolean check for a specific feature/quota
POST /v1/entitlements/offline-lease issue a signed offline lease (if not suspended/revoked)
GET  /v1/entitlements/keys          published verification keys (versioned, public)
```

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

## Offline doctrine

- Local writing remains available regardless of cloud/billing state.
- Cloud features require a current or recently cached entitlement.
- An expired subscription never blocks manuscript access.
- Revocation prevents issuing **new** leases.
- Defaults (configurable): snapshot lifetime **24h** (`ENTITLEMENT_SNAPSHOT_TTL_HOURS`),
  offline grace **7–14 days** (`OFFLINE_GRACE_DAYS`, default 14).

## Exit criteria

- Entitlement precedence is deterministic.
- Signed snapshots verify; forged snapshots fail verification.
- A suspended customer receives no new lease.
- Local-only access rules are independent from cloud availability.
