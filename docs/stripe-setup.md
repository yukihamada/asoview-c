# Stripe Integration

asoview-c integrates with Stripe for payment processing and automatic refunds on cancellation.

## Flow

```
Client                 asoview-c              Stripe
  │                       │                     │
  ├─ POST /bookings ──────►│                     │
  │                       ├─ create PaymentIntent►│
  │  ◄── {client_secret} ─┤◄─ {pi_xxx} ─────────┤
  │                       │                     │
  ├─ confirm payment ─────────────────────────► │
  │                       │ ◄─ payment_intent   │
  │                       │    .succeeded event─┤
  │                       ├─ update status=confirmed
  │                       ├─ send confirmation email
  │                       │                     │
  ├─ PATCH /bookings/:id/cancel ──────────────► │
  │                       ├─ POST /v1/refunds ──►│
  │  ◄── {refunded:true} ─┤                     │
```

## Stripe Dashboard Setup

1. Sign in at https://dashboard.stripe.com
2. Enable **Test mode** for development, **Live mode** for production
3. Go to **Developers** → **API keys** → copy **Secret key** (`sk_live_...` or `sk_test_...`)
4. Go to **Developers** → **Webhooks** → **Add endpoint**
   - URL: `https://yourdomain.com/api/v1/webhooks/stripe`
   - Events to listen: `payment_intent.succeeded`
   - Copy the **Signing secret** (`whsec_...`)

## Environment Variables

```bash
STRIPE_SECRET_KEY=<your_stripe_secret_key>
STRIPE_WEBHOOK_SECRET=<your_webhook_signing_secret>
```

## Local Webhook Testing

Use the Stripe CLI to forward webhooks to your local server:

```bash
stripe listen --forward-to http://localhost:3001/api/v1/webhooks/stripe
# Stripe CLI gives you a temporary whsec_... — set it as STRIPE_WEBHOOK_SECRET
```

## Behavior Without Stripe

When `STRIPE_SECRET_KEY` is not set:
- `POST /api/v1/bookings` immediately creates a booking with `status: "confirmed"`
- No PaymentIntent is created; no `client_secret` in response
- Confirmation email is sent immediately (if email is configured)

When `STRIPE_SECRET_KEY` is set but `STRIPE_WEBHOOK_SECRET` is missing:
- A warning is logged at startup
- Webhook endpoint will reject all events (HMAC verification fails → 400)

## Refund on Cancellation

When `PATCH /api/v1/bookings/:id/cancel` is called and the booking has a `stripe_payment_intent_id`:

1. A full refund is issued via `POST https://api.stripe.com/v1/refunds`
2. Response includes `"refunded": true`
3. Cancellation email includes a refund notice

If Stripe is not configured or the payment intent ID is missing, the booking is cancelled without a refund attempt.

## Supported Participant Types

| type | label |
|---|---|
| `adult` | 大人 |
| `child` | 子供 |
| `senior` | シニア |

Prices per type are configured via `PUT /api/v1/admin/plans/:id/prices`.

## Test Cards (Stripe Test Mode)

| Card number | Behavior |
|---|---|
| `4242 4242 4242 4242` | Success |
| `4000 0000 0000 0002` | Declined |
| `4000 0025 0000 3155` | 3D Secure required |

Use any future expiry date and any 3-digit CVC.
