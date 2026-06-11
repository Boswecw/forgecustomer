# PRIVACY.md — privacy, consent & deletion

## Tables (migration `0008_privacy.sql`)

`policy_versions`, `consent_records`, `account_deletion_requests`.

## Consent

`policy_versions` records each version of a policy (terms, privacy, etc.).
`consent_records` links a customer to the policy version they accepted, with timestamp and
source. Customers can read their own consent records (RLS); they cannot alter history.

## Deletion workflow (implemented)

```
customer requests deletion        POST /v1/account/deletion-request   (state: requested)
  → identity verified             admin advance                       (state: verified)
  → cooling-off period stamped    admin advance                       (state: cooling_off)
  → window elapsed                admin advance                       (state: processing)
  → subscriptions confirmed terminal (cancel at Stripe + resync; execute refuses otherwise)
  → EXECUTE                       admin execute — one transaction:
      profile PII anonymized (status: anonymized; display name/locale nulled)
      contact emails deleted
      devices revoked, labels stripped
      licenses revoked with explicit license_revocations records
      installations deactivated, activations released
      entitlement overrides deactivated
      PII-free deletion receipt written
      customer_anonymized outbox event queued (DataForge)
      deletion_completed audit record written
                                                                      (state: completed)
```

### States

`requested` → `verified` → `cooling_off` → `processing` → `completed`. Terminal
alternatives: `rejected` (operator, before processing), `canceled` (customer, before
processing). The pure transition rules live in `api/src/domain/deletion.rs`.

Cooling-off is deliberately **non-destructive** — nothing is suspended or revoked until
execution — so a customer cancel during the window restores nothing because nothing was
touched. Commercial state freezes at the point of no return (`processing` → execute).
The cooling-off window is `DELETION_COOLING_OFF_DAYS` (default 14); advancing into
`processing` fails closed while it has not elapsed.

External steps recorded in the receipt but performed outside this service: the Supabase
Auth user is deleted/disabled by the operator, and Stripe subscriptions are canceled at
Stripe (the execute guard verifies the local projection is terminal). Anonymized
accounts fail closed at the auth boundary (`FORBIDDEN`).

## Rules

- Do not delete legally required accounting records unlawfully; retain with an explicit,
  documented exception and anonymize linkage where possible.
- Remove or anonymize identifiers wherever retention is unnecessary.
- Maintain a **deletion receipt**.
- Do not promise instant deletion while dependent systems remain pending; track downstream
  anonymization state.

## Retention exceptions (explicit)

| Data                         | Action on deletion          | Reason                       |
| ---------------------------- | --------------------------- | ---------------------------- |
| Direct PII (email, name)     | delete / anonymize          | no ongoing need              |
| Invoice / tax references     | retain (anonymized linkage) | statutory accounting period  |
| Commercial audit events      | retain, redact PII fields   | append-only integrity        |
| Usage ledger                 | retain aggregates, drop PII | billing correctness          |

## Customer export

Customers can request a machine-readable export of their ForgeCustomer-owned data
(profile, subscription summary, licenses, installations, usage summary, consent records).
The export process is documented here and produced by the account service.

## Exit criteria (status)

- ✅ Deletion workflow is testable (full lifecycle proven live: request, cancel,
  re-request, advance, reject, execute, fail-closed guards).
- ✅ Customer export process is documented (production by the account service).
- ✅ Retention exceptions are explicit (table above; receipt records them per deletion).
- ✅ Downstream anonymization is tracked (`customer_anonymized` outbox event with
  idempotent delivery key per request).
