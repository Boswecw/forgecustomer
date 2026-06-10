# DATA_AUTHORITY.md — ownership boundaries

This document is the contract for *who owns what*. When in doubt, this file wins. There
must be **no unresolved data-ownership overlap**.

## Authorities

### Supabase Auth — login identity
Authoritative for: login identity, email verification, password reset, sessions, refresh
tokens, authentication provider identities. ForgeCustomer trusts Supabase-issued JWTs
(validated by issuer/audience/signature/expiry) but keeps its **own** business customer
ID — it never uses `auth.users.id` as the sole business identifier.

### ForgeCustomer PostgreSQL — customer & commercial truth
Authoritative for: customer records, subscriptions, licenses, installations, devices,
entitlements, quotas, usage accounting, commercial audit records.

### Stripe — payment processing
Authoritative for: payment processing, invoices, payment methods, raw payment events.
ForgeCustomer stores a **normalized** projection of Stripe state (subscription status,
period bounds, references) used by products. ForgeCustomer never stores raw card data.

### DataForge — operational evidence (sink only)
Receives sanitized operational and commercial events through the outbox. **DataForge must
never become the source of truth** for customer identity, licensing, or subscriptions.

## Ownership matrix

| Concept                         | Owner            | Notes                                  |
| ------------------------------- | ---------------- | -------------------------------------- |
| Login identity / sessions       | Supabase Auth    | JWTs validated, not minted, by us      |
| Customer profile / status       | ForgeCustomer DB | separate business `customer_id`        |
| Subscription state              | ForgeCustomer DB | normalized from Stripe webhooks        |
| Payment / invoice / card        | Stripe           | we store references only               |
| License / installation / device | ForgeCustomer DB | append-only activation/revocation log  |
| Entitlement decision            | ForgeCustomer DB | signed snapshots issued to clients     |
| Usage ledger / quotas           | ForgeCustomer DB | append-only events; derived totals     |
| Commercial audit                | ForgeCustomer DB | append-only                            |
| Manuscript / creative content   | **AuthorForge**  | never stored in ForgeCustomer          |
| Diagnostics / findings / repair | **other systems**| never stored in ForgeCustomer          |
| Operational evidence            | DataForge        | sink only, sanitized                   |

## Explicitly out of scope for ForgeCustomer

Manuscripts, creative project content, diagnostics, findings, operational repair data,
Sentinel records, general ecosystem knowledge, prompt content. No such tables exist or
will be added here.

## Explicitly out of scope for DataForge

Customer identity, licensing, subscriptions. No customer-identity tables are planned for
DataForge. The outbox payload prohibits PII (see `docs/SECURITY.md` and Phase 11).

## Mandatory architecture decisions

- ForgeCustomer is a **separate Supabase project**.
- All privileged mutations pass through the ForgeCustomer API.
- Customer clients never receive the service-role key.
- Stripe secrets remain server-side.
- Usage events are append-only.
- Audit records are append-only.
- Local creative data is never stored here.

## Exit criteria (Phase 0)

- [x] No unresolved data-ownership overlap (this matrix is authoritative).
- [x] No customer-identity tables planned for DataForge.
- [x] No manuscript / creative-content tables planned for ForgeCustomer.
