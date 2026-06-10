## 5. Data Model

Supabase/PostgreSQL is the authoritative store for customer and commercial state. The
schema is additive and deterministic under `supabase/migrations`.

### Migration domains

| Migration | Domain | Primary tables |
| --- | --- | --- |
| `0001_customer_identity.sql` | Customer identity projection | `customer_profiles`, `customer_status_history`, `customer_emails` |
| `0002_product_catalog.sql` | Product catalog | `products`, `product_versions`, `features`, `plans`, `plan_versions`, `plan_features`, `plan_quotas`, `release_channels` |
| `0003_commerce.sql` | Commerce and Stripe projection | `billing_accounts`, `stripe_customers`, `subscriptions`, `subscription_items`, `billing_periods`, `checkout_sessions`, `invoice_references`, `stripe_webhook_events` |
| `0004_licensing.sql` | Licenses, installations, devices | `licenses`, `license_grants`, `devices`, `installations`, `license_activations`, `license_leases`, `license_revocations` |
| `0005_entitlements.sql` | Entitlements | `entitlement_grants`, `entitlement_overrides`, `entitlement_snapshots` |
| `0006_usage.sql` | Usage and quotas | `usage_meters`, `usage_reservations`, `usage_events`, `usage_period_totals`, `quota_decisions` |
| `0007_audit_outbox.sql` | Audit and outbox | `commercial_audit_events`, `outbox_events` |
| `0008_privacy.sql` | Privacy and deletion | `policy_versions`, `consent_records`, `account_deletion_requests` |
| `0009_rls.sql` | Row-level security | Enables and forces RLS; creates own-row and public-catalog policies. |
| `0010_seed_constraints.sql` | Determinism and indexes | Adds seed/constraint hardening and operational indexes. |

### RLS posture

RLS is enabled and forced across public tables. Customer-facing records are scoped by the
business `customer_id`, not only by the Supabase auth subject. Catalog tables are public
read. CI asserts that all public tables have RLS enabled.

The API still owns privileged writes. RLS is defense in depth, not a substitute for the
server-side authorization model.

### Append-only state

Append-only tables are part of the commercial trust boundary:

- `usage_events`
- `commercial_audit_events`
- webhook/event receipt tables where replay protection matters
- outbox delivery records, except operational status fields required for retry/dead-letter

Corrections must be represented by new compensating events, never by silently editing the
authoritative ledger.

### Catalog seed model

Products, plan versions, features, quotas, and release channels are seeded
deterministically. Adding a future product should be data-first: insert product/catalog
rows and only add schema when a genuinely new domain concept exists.

### Repository layer

The Rust API uses SQLx runtime query APIs. The crate does not require a live database for
compile-time query macro verification. Repository functions currently cover customer
profile lookup and catalog list operations; additional DB-backed endpoints should add
repository functions rather than embedding ad hoc SQL in route handlers.
