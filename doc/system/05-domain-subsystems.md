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

Profile provisioning is the controlled exception: `POST /v1/account/provision` validates
the Supabase JWT, inserts one `customer_profiles` row for the token subject, writes an
initial `customer_status_history` row, projects the trusted Supabase email claim into
`customer_emails` when present, and returns the existing profile on repeat calls. The
endpoint accepts only display/localization decoration; customer type and commercial status
remain server-owned.

### Commerce and Stripe

Stripe owns payment processing. ForgeCustomer stores normalized subscription projection
used by product clients.

Current pure logic maps Stripe subscription statuses into ForgeCustomer statuses and
determines whether a status grants cloud access. Checkout creation is live for active paid
catalog plans: the API resolves `plan_versions.stripe_price_id`, calls Stripe with the
server-side secret, stores the returned session id, and returns the hosted URL. Webhook
processing is also live: the API verifies `Stripe-Signature`, parses a minimal non-PII
event summary, stores the event id once, marks unsupported events ignored, and applies
supported checkout/subscription/invoice events in one transaction. Subscription changes
write normalized projection rows, commercial audit, and sanitized `subscription_changed`
outbox events. Only verified Stripe webhooks may change subscription truth; browser
redirects must only confirm that the customer returned from Stripe.

### Licensing and installations

The model keeps licenses, installations, devices, activations, leases, and revocations as
distinct concepts.

Implemented behavior:

- Subscription-linked licenses are issued and kept in sync by verified webhook processing
  only: cloud-granting statuses issue/reactivate, `past_due` is a dunning grace window,
  `unpaid`/`paused`/`incomplete` suspend, `canceled` expires, and a revoked license is
  never changed by subscription state. The device limit comes from the plan version's
  `<product>.devices.max` feature (default 1).
- Registration is idempotent by client-supplied install key; an optional base64 Ed25519
  public key (validated to 32 bytes, fingerprinted with SHA-256) upserts device identity.
  Re-registering a deactivated installation reactivates the installation record only.
- Activation locks the license row, then fails closed in order: deactivated installation,
  revoked device, revoked/suspended/expired license, explicit `license_revocations` row
  (license-, installation-, or device-scoped), and finally the device limit. An
  already-active pairing returns idempotently.
- Customers deactivate old installations to free slots; deactivation releases the
  installation's active activations.
- Activation, deactivation, and every license sync mutation write commercial audit;
  registration and activation also queue sanitized outbox events.
- Offline leases are time-bound and denied for suspended or revoked contexts; lease
  issuance wiring lands with the entitlement snapshot work.

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
