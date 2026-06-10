# LICENSING.md — licensing, installations, devices

These concepts are **distinct** and never collapsed into one table:

| Concept       | Meaning                                          |
| ------------- | ------------------------------------------------ |
| License       | a product-use grant                              |
| Installation  | an installed application instance                |
| Device        | a machine identity (public key)                  |
| Activation    | a link between a license and an installation     |
| Lease         | a signed temporary offline permission            |
| Revocation    | an explicit denial record                        |

## Tables (migration `0004_licensing.sql`)

`licenses`, `license_grants`, `installations`, `devices`, `license_activations`,
`license_leases`, `license_revocations`.

## Device identity

- The product client generates a keypair locally and stores the **private** key in the OS
  keyring.
- The **public** key is registered with ForgeCustomer.
- Activation and lease requests are signed by the client; ForgeCustomer verifies.
- Hardware fingerprints are not used as primary identity.

## Installation routes (live)

```
POST   /v1/installations                  register; idempotent (by client-supplied install_key)
GET    /v1/installations
POST   /v1/installations/{id}/activate    links license ↔ installation, enforces device cap
POST   /v1/installations/{id}/heartbeat   liveness; may refresh reported app_version
POST   /v1/installations/{id}/deactivate  releases the installation's activations
GET    /v1/devices
GET    /v1/licenses
```

## License issuance and sync (subscription-linked)

Licenses linked to a subscription are managed exclusively by verified Stripe webhook
processing (`api/src/repositories/licensing.rs::sync_license_for_subscription`, called
inside the webhook transaction). The transition rules are pure logic in
`api/src/domain/license.rs::license_sync_action`:

| Subscription status        | Missing license | Active license | Suspended/expired license |
| -------------------------- | --------------- | -------------- | ------------------------- |
| `active` / `trialing`      | issue           | keep (refresh device limit on plan change) | reactivate |
| `past_due` (dunning grace) | —               | keep           | — |
| `unpaid` / `paused` / `incomplete` | —       | suspend        | — |
| `canceled`                 | —               | expire         | suspended → expire |

A **revoked** license is never changed by subscription state — revocation is an explicit
denial that only an operator action may lift. The device limit is read from the plan
version's `<product>.devices.max` feature (default 1 when absent). Every sync mutation
writes a `commercial_audit_event` (`license_issued`, `license_reactivated`,
`license_suspended`, `license_expired`, `license_device_limit_changed`).

## Registration

- Idempotent on `(customer_id, install_key)`; the install key is client-generated
  (8–120 chars of `[A-Za-z0-9._:-]`).
- An optional base64 Ed25519 public key upserts the device row by
  `(customer_id, public_key_fpr)` (fingerprint = SHA-256 hex of the raw key bytes);
  the key is validated to decode to exactly 32 bytes.
- Re-registering a deactivated installation reactivates the installation record itself —
  device slots are only consumed by activation.
- Re-registering an existing install key for a *different* product is a `409 CONFLICT`.
- First registration queues the sanitized `installation_registered` outbox event
  (no label, no PII).

## Activation rules (fail closed)

- The installation must exist, belong to the caller, and be `active`
  (deactivated → `409`; re-register first).
- With no explicit `license_id`, the most recently issued active, unexpired license for
  the installation's product is selected.
- The license row is locked (`select … for update`) for the whole check-then-insert, so
  concurrent activations serialize and cannot oversubscribe the device limit.
- Denials, in order: revoked device → `REVOKED`; revoked license → `REVOKED`;
  suspended/expired license → `FORBIDDEN`; matching `license_revocations` row (scoped to
  the whole license, this installation, or this device) → `REVOKED`; device limit full →
  `DEVICE_LIMIT_REACHED` (402).
- Re-activating an already-active (license, installation) pair is idempotent
  (`already_active: true`); it writes no duplicate activation, audit, or outbox row.
- Successful activation writes the `license_activated` audit event and the sanitized
  `license_activated` outbox event in the same transaction.

## Deactivation

- Idempotent; marks the installation `deactivated` and releases all of its active
  `license_activations` (freeing device slots), with an `installation_deactivated`
  audit event.

## Exit criteria (status)

- ✅ Device limits enforced; duplicate registration idempotent.
- ✅ Revoked devices cannot reactivate silently (`license_revocations` + device status
  checked on every activation).
- ✅ Customer can deactivate an old installation to free a slot.
- ✅ Audit records exist for activation, deactivation, and license issuance/sync;
  revocation audit lands with the admin revoke endpoint (Phase 10).
- 🔜 Offline-lease issuance (`POST /v1/entitlements/offline-lease`) lands with the
  Phase 7 entitlement snapshot work; `DELETE /v1/installations/{id}` is deferred
  (deactivate covers the MVP).
