# Email Setup (Resend)

asoview-c uses [Resend](https://resend.com) for transactional email via a direct REST API call (no SMTP dependency).

## Emails Sent

| Trigger | Recipient | Template |
|---|---|---|
| `POST /api/v1/auth/forgot-password` | Registered user | Password reset link |
| `POST /api/v1/bookings` (no Stripe) | Booking user | Booking confirmation |
| Stripe `payment_intent.succeeded` webhook | Booking user | Booking confirmation |
| `PATCH /api/v1/bookings/:id/cancel` | Booking user | Cancellation notice (with/without refund) |

## Configuration

Set the following environment variables:

```bash
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
RESEND_FROM=info@yourdomain.com        # must be a verified sender domain
FRONTEND_URL=https://yourdomain.com    # used for password reset links
```

## Resend Setup

1. Sign up at https://resend.com
2. Go to **Domains** → Add your domain → verify DNS records (SPF, DKIM, DMARC)
3. Go to **API Keys** → Create key → copy `re_...` value
4. Set `RESEND_FROM` to any address at your verified domain (e.g., `info@yourdomain.com`)

## Development / Test Mode

When `RESEND_API_KEY` is not set, the server:
- Skips email delivery (logs to stderr: `[mailer] RESEND_API_KEY 未設定 — メール送信をスキップ`)
- Returns `reset_token` in the `POST /forgot-password` response body (for testing without email)

```json
{
  "message": "パスワードリセットメールを送信しました",
  "reset_token": "abc123..."
}
```

In production with `RESEND_API_KEY` set, `reset_token` is **not** included in the response.

## Email Templates

Templates are embedded in `src/mailer.c` as HTML strings. To customize:

1. Edit the template strings in `src/mailer.c`
2. Rebuild: `make release`

### Password Reset Email

- Subject: `パスワードリセット — asoview`
- Contains a link: `${FRONTEND_URL}/reset-password?token=<token>`
- Token expires in 1 hour

### Booking Confirmation Email

- Subject: `予約確定のお知らせ — <plan title>`
- Contains: booking ID, plan title, date, start time, total price

### Cancellation Email

- Subject: `予約キャンセルのご連絡 — <plan title>`
- Indicates whether a Stripe refund was processed

## Troubleshooting

| Symptom | Check |
|---|---|
| Emails not delivered | Verify domain DNS in Resend dashboard |
| `401 Unauthorized` from Resend | Check `RESEND_API_KEY` value |
| Wrong From address | Verify `RESEND_FROM` domain is verified in Resend |
| Reset link broken | Verify `FRONTEND_URL` has no trailing slash |
