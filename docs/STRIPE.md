# STRIPE.md — commerce & Stripe integration

Stripe owns payments; ForgeCustomer stores a **normalized** projection of subscription
state. Only verified webhook processing changes subscription truth.

Current implementation status: Checkout Session creation, signature verification, event
parsing, idempotent receipt, duplicate detection, unsupported-event ignoring, subscription
projection, invoice reference recording, commercial audit writes, and sanitized
`subscription_changed` outbox emission are live.

## Tables (migration `0003_commerce.sql`)

`billing_accounts`, `stripe_customers`, `subscriptions`, `subscription_items`,
`billing_periods`, `checkout_sessions`, `invoice_references`, `stripe_webhook_events`.

## Subscription status normalization

Stripe status → ForgeCustomer status:

| Stripe                | ForgeCustomer |
| --------------------- | ------------- |
| `trialing`            | `trialing`    |
| `active`              | `active`      |
| `past_due`            | `past_due`    |
| `unpaid`              | `unpaid`      |
| `canceled`            | `canceled`    |
| `incomplete`          | `incomplete`  |
| `incomplete_expired`  | `canceled`    |
| `paused`              | `paused`      |

## Checkout flow

```
Client → POST /v1/checkout
  → API validates customer + plan version
  → API creates Stripe Checkout Session (server-side, secret key)
  → checkout_sessions row stored (reference only)
  → returns redirect URL
```

The browser redirect **does not** activate entitlements. Checkout requests resolve the
active `plan_versions.stripe_price_id` server-side; customers cannot submit arbitrary
Stripe price ids.

## Webhook flow

```
Stripe → POST /v1/webhooks/stripe
  → verify signature (constant-time, STRIPE_WEBHOOK_SECRET)
  → store event id in stripe_webhook_events (dedupe)
  → if duplicate: ack 200, do nothing
  → if unsupported: mark ignored, ack 200
  → BEGIN tx
      → normalize subscription state or invoice payment state
      → update checkout/session/invoice references as applicable
      → write commercial_audit_event
      → write sanitized subscription_changed outbox_event when status changes
      → mark webhook processed
    COMMIT
  → ack 200
```

Required events: `checkout.session.completed`, `customer.subscription.created`,
`customer.subscription.updated`, `customer.subscription.deleted`, `invoice.paid`,
`invoice.payment_failed`.

## Mandatory rules

- Browser redirect does not activate entitlements.
- Customers cannot provide Stripe price ids directly; paid plan selection is catalog-backed.
- Only verified webhook processing changes subscription truth.
- Duplicate webhooks are safe (dedupe by Stripe event id).
- Unsupported event types are acknowledged and ignored explicitly.
- Out-of-order events are handled (compare event/object timestamps; never regress to a
  staler state).
- Raw card data is never stored.
- Raw webhook payload retention is minimal and secured.

## Exit criteria

- Successful Checkout creates the correct subscription.
- Duplicate events do not duplicate state.
- Failed payments update commercial status (`past_due` / `unpaid`).
- Cancellation revokes future cloud entitlement; existing local content stays accessible.
