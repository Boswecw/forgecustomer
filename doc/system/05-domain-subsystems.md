## 6. Domain Subsystems

The service separates pure domain rules from route wiring. Pure logic is testable without
Stripe, Supabase, or a live database.

### Customer identity

Supabase Auth owns login identity. ForgeCustomer owns business customer profiles and
status. Customer route access requires:

1. Valid Supabase JWT.
2. Token subject parseable as a UUID.
3. Matching `customer_profiles.auth_user_id`.
4. Non-suspended status for privileged product actions.

Missing profile fails closed as `FORBIDDEN`.

### Commerce and Stripe

Stripe owns payment processing. ForgeCustomer stores normalized subscription projection
used by product clients.

Current pure logic maps Stripe subscription statuses into ForgeCustomer statuses and
determines whether a status grants cloud access. Checkout and webhook handlers are still
pending. When implemented, only verified Stripe webhooks may change subscription truth;
browser redirects must only confirm that the customer returned from Stripe.

### Licensing and installations

The model keeps licenses, installations, devices, activations, leases, and revocations as
distinct concepts.

Required behavior:

- Device activation enforces plan/device limits.
- Duplicate registration is idempotent.
- Revoked devices cannot silently reactivate.
- Customers can deactivate old installations to free a slot.
- Activation/revocation writes commercial audit.
- Offline leases are time-bound and denied for suspended or revoked contexts.

Route wiring for these flows is pending.

### Entitlements

Entitlements are evaluated deterministically from lower-precedence defaults to
higher-precedence overrides:

```text
product defaults
  -> plan version features and quotas
  -> active subscription cloud gates
  -> license grants
  -> promotional grants
  -> admin overrides
  -> suspension/revocation denials
  -> signed entitlement snapshot
```

Suspension and revocation always deny cloud/new-lease capabilities. Local product access
is evaluated independently and must not be revoked by commercial state.

`Signer25519` signs canonical entitlement snapshots and `VerifyingKeyRing` verifies them.
`GET /v1/entitlements/keys` publishes active verification keys. Snapshot assembly from
plan/grant/override database rows remains pending.

### Usage and quotas

Usage accounting is ledger-first:

- `usage_events` is authoritative and append-only.
- `usage_period_totals` is a rebuildable optimization.
- `usage_reservations` holds in-flight quota.
- `quota_decisions` records explainable allow/deny decisions.
- Meter units must be explicit.

The pure usage decision logic is implemented. Reserve/commit/release/current endpoints
remain pending.

### Privacy and deletion

The schema includes policy versions, consent records, and account deletion requests.
Deletion must anonymize/delete direct PII while preserving legally required accounting
records with explicit exceptions. Downstream deletion/anonymization events must be
sanitized before entering the outbox.

### Admin operations

Admin APIs use a separate operator issuer and audience. A future admin mutation must:

- Validate operator authorization.
- Require a reason for material commercial changes.
- Write commercial audit.
- Preserve append-only ledgers.
- Emit a sanitized outbox event when downstream evidence is required.
