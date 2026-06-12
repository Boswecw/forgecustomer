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

Self-service subscription management is offered through the **Stripe Billing Customer
Portal**, not bespoke endpoints. `POST /v1/billing-portal` resolves the caller's linked
Stripe customer (via `stripe_customers` → `billing_accounts`) and mints a portal session;
the customer cancels, switches plan, or updates payment on Stripe's hosted page. This keeps
the invariant intact — the door changes nothing, and the resulting cancel/downgrade flows
back through the existing webhook path that reprojects subscription truth and re-syncs the
linked license. A customer with no Stripe linkage yet returns `NO_BILLING_ACCOUNT`.

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

### Fleets, releases, and updates

ForgeCustomer owns fleet assignment and update eligibility. Clients may identify their
owned installation, current version/build, platform, architecture, package format, and
updater version, but they may not claim an arbitrary fleet.

Implemented behavior:

- Account provisioning and installation registration create/resolve a default active
  fleet and AuthorForge fleet application policy.
- Release-pipeline intake registers draft release metadata idempotently by
  product/version/build, then registers immutable bootstrap/updater/recovery artifact
  metadata after upload/checksum/signature proof.
- Release publication is operator-controlled: validation requires at least one validated
  artifact, and publication requires validated release state.
- Public website/bootstrap lookup exposes only published releases with validated generic
  bootstrap artifacts; it never embeds customer, fleet, or personalized license state.
- Campaigns are created at `0%` rollout and move through explicit audited controls
  (`pause`, `resume`, `revoke`, rollout changes, and fleet holds).
- Dynamic update lookup returns `204` unless every gate passes: active installation/fleet,
  active fleet application, published release, validated artifact, matching channel/ring,
  no fleet hold, matching target/architecture/package, version requirements, and the
  deterministic server-side HMAC rollout bucket.
- Update outcome receipts store only bounded enum/code/version/build fields with UUID
  idempotency. Raw diagnostics, stack traces, hostnames, paths, logs, and creative
  content are rejected.

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

Implemented behavior:

- Snapshot assembly maps the layers onto data: the product's `<product>_included` plan
  is the baseline; the current subscription (cloud-granting preferred, canceled excluded)
  contributes its plan version; license grants come from active unexpired licenses;
  promotional grants and admin overrides apply last. Quota limits merge in the same
  order, and monthly meters surface committed usage as `<meter>.used`.
- Suspension is rejected at the auth boundary (`CUSTOMER_SUSPENDED`); a revoked latest
  license forces cloud features off in evaluation.
- `Signer25519` signs canonical snapshots and leases; `VerifyingKeyRing` verifies and
  `GET /v1/entitlements/keys` publishes active verification keys. Issued snapshots are
  stored in `entitlement_snapshots`; responses preserve the canonical field order so
  clients can verify the signature from the received document.
- Advisory feature/quota checks are read-only and fail closed.
- Offline leases (`forge.lease.v1`) are issued only to active installations holding an
  active activation on an active, unexpired license, with no revocation in scope; each
  issuance stores the lease row and a `lease_issued` audit event transactionally. Lease
  lifetime is the configured offline grace window.

### Usage and quotas

Usage accounting is ledger-first:

- `usage_events` is authoritative and append-only.
- `usage_period_totals` is a rebuildable optimization.
- `usage_reservations` holds in-flight quota.
- `quota_decisions` records explainable allow/deny decisions.
- Meter units must be explicit.

Implemented behavior:

- Limits resolve from the assembled entitlement quotas (cadence-qualified key first);
  uncataloged quota rows leave a meter uncapped, while the included plan zeroes the paid
  meters for free customers.
- Reserve and direct commit share one decision path under a `(customer, meter, period)`
  totals lock; every decision (allow and deny) is recorded in `quota_decisions`.
- Reservations dedupe on `(customer, idempotency key)`, commits dedupe the same pair in
  the ledger; replays return the original row and never double-charge.
- Stale pending reservations expire lazily inside that lock and via the
  `workers::usage` background sweeper; committing an expired reservation fails closed
  and frees its hold.
- Threshold crossings queue `quota_threshold_reached` once per
  (customer, meter, period, threshold); denied direct commits queue
  `usage_commit_failed`.
- Period totals are derived and were verified live to equal the ledger sum.

### Privacy and deletion

The schema includes policy versions, consent records, and account deletion requests.

Implemented behavior:

- The state machine (`requested → verified → cooling_off → processing → completed`,
  with `rejected`/`canceled` terminals) is pure logic in `domain::deletion`; customers
  request and cancel, operators advance, reject, and execute.
- Cooling-off is non-destructive so a customer cancel restores nothing; the window is
  stamped on entry and entering `processing` fails closed while it has not elapsed.
- Execution anonymizes in one transaction — profile PII, contact emails, device labels
  (devices revoked), licenses revoked with explicit revocation records, installations
  deactivated, overrides deactivated — writes a PII-free receipt with the retention
  exceptions, queues the sanitized `customer_anonymized` event, and audits
  `deletion_completed`. It refuses while a non-terminal subscription remains.
- Legally required accounting records (billing/invoice references, audit, usage ledger,
  consent records) are retained per `docs/PRIVACY.md`; anonymized accounts fail closed
  at the auth boundary.

### Admin operations

Admin APIs use a separate operator issuer and audience (Forge Command). Every
implemented admin mutation:

- Validates operator authorization (mutations additionally require the `admin` role).
- Requires a written reason for material commercial changes.
- Writes operator-actor commercial audit.
- Preserves append-only ledgers (usage corrections are compensating adjustment events
  behind a required idempotency key).
- Emits a sanitized outbox event where the event contract defines one.
