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

## Installation routes

```
POST   /v1/installations/register        idempotent (by client-supplied install key)
GET    /v1/installations
POST   /v1/installations/{id}/activate    links license ↔ installation, enforces device cap
POST   /v1/installations/{id}/heartbeat   liveness; may refresh short-lived state
POST   /v1/installations/{id}/deactivate
DELETE /v1/installations/{id}
```

## Rules

- Device limits are enforced from plan features (`authorforge.devices.max`).
- Revoked devices cannot reactivate silently — a `license_revocations` row blocks new
  activations/leases and is checked on every activation.
- Duplicate registration is idempotent.
- A customer may deactivate an old installation to free a device slot.
- Activation and revocation always write a `commercial_audit_event`.

## Exit criteria

- Device limits enforced; duplicate registration idempotent.
- Revoked devices cannot reactivate silently.
- Customer can deactivate an old installation.
- Audit records exist for activation and revocation.
