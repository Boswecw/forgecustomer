## 2. Authority Boundaries

ForgeCustomer exists to remove data-ownership ambiguity. Each authority has a narrow
role, and the API must preserve those boundaries even when integrations fail.

### Sources of truth

| Authority | Owns | Does not own |
| --- | --- | --- |
| Supabase Auth | Login identity, email verification, sessions, refresh tokens, provider identities. | Business customer status, subscriptions, licenses, usage, entitlements. |
| ForgeCustomer PostgreSQL | Customer profiles, commercial status, subscriptions projection, licenses, installations, devices, fleets, release eligibility, update campaigns/outcomes, entitlements, quotas, usage ledger, audit, deletion workflow. | Raw payment processing, card data, manuscripts, prompts, operational repair findings. |
| Stripe | Payment processing, invoices, payment methods, raw payment events. | Product entitlement truth, device activation, local content access. |
| DataForge | Sanitized downstream evidence from the outbox. | Customer identity, licensing, subscriptions, billing truth, creative content. |
| AuthorForge and product clients | Local creative work and local product state. | Commercial authority, entitlement minting, usage-ledger mutation. |
| Forge Command/operator tooling | Operator workflows through admin APIs. | Bypassing ForgeCustomer mutation paths. |

ForgeCustomer PostgreSQL is the customer and commercial source of truth.

### Boundary rules

- `auth.users.id` is an identity subject, not the business customer identifier.
  ForgeCustomer maps it to its own `customer_profiles.id`.
- Customer JWTs are valid only for customer routes. Admin routes use a separate issuer,
  audience, and secret.
- Customer clients may read their own commercial state but may not directly write
  subscriptions, Stripe mappings, licenses, entitlement grants, usage totals, audit
  records, or outbox events.
- Stripe webhooks normalize payment state into ForgeCustomer tables. Stripe remains the
  payment processor, but ForgeCustomer owns product-facing subscription projection.
- DataForge is a sink. It receives pseudonymous sanitized events; it must never be used
  to reconstruct or override commercial truth.
- Local creative data never crosses into ForgeCustomer. Product access doctrine must
  preserve local work when cloud or billing systems are unavailable.

### Explicitly out of scope

ForgeCustomer must not introduce tables, APIs, logs, outbox payloads, or documents that
store or imply ownership over:

- Manuscripts or creative project content.
- Prompt content or model-output text.
- Diagnostics, findings, repair data, Sentinel records, or ecosystem knowledge.
- Raw card data, payment methods, passwords, refresh tokens, or Supabase service-role
  keys.

### Conflict resolution

If implementation pressure creates overlap, resolve it by moving the data to the owning
system rather than expanding ForgeCustomer. A new table or endpoint is acceptable only
when it preserves the authority matrix above and has a corresponding migration,
contract/doc update, and test.
