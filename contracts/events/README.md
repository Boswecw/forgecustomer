# Event contracts

Sanitized events ForgeCustomer emits to DataForge through the transactional outbox.

- [`outbox-event-v1.schema.json`](outbox-event-v1.schema.json) — the delivery envelope and
  the allowed `event_type` set. The schema encodes the **prohibited keys** rule: payloads
  must never contain PII, secrets, payment details, or creative content. The API enforces
  the same rule in code (`domain::redaction`) and again at publish time
  (`integrations::dataforge`).

## Example

```json
{
  "event_type": "subscription_changed",
  "delivery_key": "sub_changed:cust_123:evt_abc",
  "payload": {
    "customer_id": "cust_123",
    "product": "authorforge",
    "status": "active",
    "plan_key": "authorforge_pro",
    "occurred_at": "2026-06-10T12:00:00Z"
  }
}
```

`customer_id` and `installation_id` are pseudonymous identifiers and are permitted; direct
identifiers (email, name, Stripe ids) are not.
