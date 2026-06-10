# SECURITY.md — security posture

## Principles

- **Fail closed.** Auth, licensing, and entitlement decisions deny on any doubt.
- **Least privilege.** The service-role key is used only inside ForgeCustomer server
  processes. It is never shipped to BDS website browser code, AuthorForge desktop code,
  Forge Command frontend, or documentation.
- **Defense in depth.** RLS + API authorization + input validation + rate limiting.
- **Secrets stay server-side.** Stripe secret key, webhook secret, service-role key, and
  the entitlement signing private key never appear in clients, logs, or repo history.

## Identity & tokens

- Customer access tokens are Supabase JWTs: short-lived, validated for **issuer**,
  **audience**, signature, and **expiry**. Invalid/expired/wrong-audience tokens fail
  closed.
- Refresh-token rotation is handled by Supabase Auth.
- Admin/operator tokens use a **separate** trusted issuer and audience
  (`ADMIN_JWT_ISSUER` / `ADMIN_JWT_AUDIENCE`). A customer token can **never** authorize an
  admin route. Admin authorization validates trusted issuer, operator identity, role /
  capability, expiration, audience, and optional device trust. No client-provided claim
  promotes a customer to admin.
- **Forge Command** is the operator console and the only intended consumer of
  `/v1/admin/*`; it works through these APIs and never bypasses ForgeCustomer mutation
  paths. Role policy (fail closed): admin **reads** require any valid operator token;
  admin **mutations** require the `admin` role in the token's `roles` claim, plus a
  written reason recorded in commercial audit with the operator id as actor.

## Customer access rules

- A customer may read only its own profile, subscription summary, licenses,
  installations, entitlement summary, usage summary, consent records, and deletion
  requests (enforced by RLS, see `docs/`/`0009_rls.sql`).
- A customer may **not** directly write subscription status, Stripe mappings, licenses,
  entitlement grants/overrides, usage events/totals, commercial audit, outbox events, or
  any admin state.

## Webhooks

- Stripe webhook signatures are verified with `STRIPE_WEBHOOK_SECRET` using
  **constant-time** comparison before any processing.
- Event IDs are stored; duplicates are detected and processed once (idempotent).
- Raw webhook payload retention is minimal and access-restricted.

## Entitlement signing

- Snapshots are signed with **Ed25519**. Private key lives in a server-side secret
  manager (`ENTITLEMENT_SIGNING_PRIVATE_KEY`); public keys are published via a versioned
  endpoint; every snapshot carries a `key_id`.
- **Key rotation** supports overlapping keys: old and new verification keys both validate
  during the rotation window.
- The private signing key must never appear in logs.

## Data protection / PII

PII classification:

| Class       | Examples                                              | Handling                          |
| ----------- | ----------------------------------------------------- | --------------------------------- |
| Direct PII  | email, full name                                      | encrypted at rest (Supabase), RLS, redacted in logs, **never** in outbox |
| Financial   | Stripe customer id, payment refs                      | server-side only, never in outbox |
| Pseudonymous| customer_id, installation_id, device public key       | safe for sanitized outbox         |
| Secret      | service-role key, Stripe keys, signing private key    | secret manager only               |

- Structured **redaction** in logs/tracing for direct PII and secrets.
- Outbox payloads **prohibit**: email, full name, Stripe customer id, payment details,
  raw webhook payload, password/session info, manuscript content, prompt content.

## Hardening checklist

Short-lived access tokens · refresh-token rotation · strict JWT issuer/audience checks ·
rate limiting · request-size limits · webhook signature verification · constant-time
verification · key rotation support · secret scanning in CI · structured redaction ·
dependency audit · database least privilege · separate dev/staging/prod secrets.

### Dependency-audit waivers

`cargo audit` runs in CI and fails the build on any new advisory. Explicit waivers live
in `.cargo/audit.toml`, each with a written justification, and are revisited whenever the
flagged dependency or its parent is upgraded. Current waivers:

- **RUSTSEC-2023-0071** (`rsa` 0.9.x, Marvin timing side-channel, no fixed 0.9 release):
  `rsa` appears in `Cargo.lock` only as a dependency of `sqlx-mysql`. This service is
  Postgres-only; `sqlx-mysql` is never enabled, and `cargo tree -i rsa` confirms the
  crate is not part of the compiled dependency graph. Lockfiles record optional
  dependencies for every feature combination, so the entry cannot be dropped while sqlx
  is a dependency. Remove the waiver when sqlx ships against a fixed `rsa`.

## Customer deletion (summary)

See `docs/PRIVACY.md`. PII is deleted/anonymized; legally required accounting records are
retained with explicit exceptions; a deletion receipt and downstream anonymization event
are produced.

## Exit criteria

- Old and new verification keys both work during the rotation window.
- Private signing key never appears in logs.
- Secrets are absent from repository history.
- Webhook-replay and forged-token tests pass.
