# PRIVACY.md — privacy, consent & deletion

## Tables (migration `0008_privacy.sql`)

`policy_versions`, `consent_records`, `account_deletion_requests`.

## Consent

`policy_versions` records each version of a policy (terms, privacy, etc.).
`consent_records` links a customer to the policy version they accepted, with timestamp and
source. Customers can read their own consent records (RLS); they cannot alter history.

## Deletion workflow

```
customer requests deletion
  → request recorded (state: requested)
  → identity verified (state: verified)
  → sessions revoked
  → licenses suspended
  → cooling-off period (state: cooling_off)
  → legally required billing records identified
  → state: processing
  → profile PII deleted or anonymized
  → DataForge anonymization event emitted (customer_anonymized)
  → completion audit record written (deletion_completed)
  → state: completed
```

### States

`requested` → `verified` → `cooling_off` → `processing` → `completed`. Terminal
alternatives: `rejected`, `canceled`.

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

## Exit criteria

- Deletion workflow is testable.
- Customer export process is documented.
- Retention exceptions are explicit (table above).
- Downstream anonymization is tracked.
