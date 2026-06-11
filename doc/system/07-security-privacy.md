## 8. Security and Privacy

ForgeCustomer is a fail-closed commercial authority. Security decisions must be explicit,
testable, and boring.

### Token validation

Customer tokens:

- Supabase-issued JWTs.
- Validated for HS256 signature, issuer, audience, and expiry.
- `sub` must parse as a UUID.
- Missing or unprovisioned customer profiles fail closed.

Admin tokens:

- Separate operator issuer and audience.
- Separate secret from customer tokens.
- A customer token cannot authorize an admin route.

If a JWT secret is absent, the validator is marked unconfigured and rejects tokens. That
prevents accidental local or production token acceptance.

### Secrets

Server-side only:

- `SUPABASE_SERVICE_ROLE_KEY`
- `SUPABASE_JWT_SECRET`
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `ENTITLEMENT_SIGNING_PRIVATE_KEY`
- `DATAFORGE_SERVICE_TOKEN`

Secrets must not appear in clients, logs, docs examples with real values, outbox payloads,
or repo history.

### Security headers

Every response receives:

- `x-content-type-options: nosniff`
- `x-frame-options: DENY`
- `referrer-policy: no-referrer`
- `strict-transport-security: max-age=31536000; includeSubDomains`

### Entitlement signing

Entitlement snapshots use Ed25519. The signing private key is loaded from
`ENTITLEMENT_SIGNING_PRIVATE_KEY`, and published keys are exposed by key ID. Key rotation
requires an overlap window where old and new public keys both verify existing snapshots.

Forged snapshots must fail verification. Private signing keys must never be logged.

### PII classification

| Class | Examples | Handling |
| --- | --- | --- |
| Direct PII | email, full name | RLS, redaction, no outbox payloads |
| Financial references | Stripe customer/payment identifiers | server-side only, no outbox payloads |
| Pseudonymous IDs | `customer_id`, `installation_id`, device public key | allowed in sanitized events |
| Secrets | API keys, JWT secrets, signing private key | secret manager/env only |
| Creative content | manuscripts, prompts, model output | never stored here |

### Failure doctrine

- Auth failure denies.
- Suspended customers receive no privileged product actions.
- Revoked devices receive no new activations/leases.
- Ambiguous entitlement state denies cloud/new lease access.
- Local creative access must remain available despite cloud, billing, or DataForge
  outages.
- DataForge outage degrades to queued outbox delivery, not failed customer transactions.
