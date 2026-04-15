# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-04-15

### Added
- CI/CD pipeline via GitHub Actions (`.github/workflows/ci.yml`) with ASAN build
- OpenAPI 3.0.3 specification (`openapi.yml`) covering all public and admin endpoints
- iCal export endpoint (`GET /api/v1/bookings/{id}/ical`) returning `text/calendar`
- Partner webhook system: register, list, and delete webhook endpoints; events dispatched on booking state changes
- Coupons / promo codes: create, list, and validate discount codes (percent or fixed amount)
- Sales report CSV export (`GET /api/v1/admin/reports/sales?from=&to=`)
- Multiple plan images: upload additional images per plan, delete individual images
- Two-factor authentication (TOTP): setup, enable, and verify flows
- Waitlist auto-confirm: automatically promote waitlisted bookings when a slot opens

## [0.3.0] - 2026-04-15

### Added
- JWT rotation support via `JWT_SECRET_PREV` environment variable (zero-downtime key rotation)
- Graceful shutdown drain: in-flight requests are allowed to complete before process exit
- Email cancellation link: booking confirmation emails now include a one-click cancel URL
- k6 load test script (`scripts/k6_load_test.js`) for performance benchmarking
- Staging environment `docker-compose.staging.yml` with separate database volumes
- Prometheus alert rules (`monitoring/alerts.yml`) for latency, error rate, and queue depth

## [0.2.0] - 2026-04-14

### Added
- Setup wizard (`GET /setup`, `POST /setup`) for first-run configuration
- Admin UI single-page application served under `/admin`
- Bulk schedule creation endpoint (`POST /api/v1/admin/plans/{id}/schedules/bulk`)
- Cursor-based pagination (`after` query parameter) on venue, plan, and booking list endpoints
- JSON structured logging (RFC 3339 timestamps, log level, request ID)
- Security headers middleware: `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`
- Database backup endpoint (`GET /api/v1/admin/backup`) streaming a gzipped SQLite snapshot
- Refund endpoint (`POST /api/v1/admin/bookings/{id}/refund`) triggering Stripe partial or full refund
- Docker Compose multi-backend configuration supporting SQLite, PostgreSQL, and MySQL profiles

## [0.1.0] - 2026-04-14

### Added
- Initial release of the Asoview C REST API server
- Written in C11 using [mongoose](https://github.com/cesanta/mongoose) as the embedded HTTP/WebSocket library and [cJSON](https://github.com/DaveGambrill/cJSON) for JSON handling
- Database backends: SQLite (default, via bundled amalgamation), PostgreSQL, and MySQL — selected at compile time via `DB=` make variable
- JWT-based authentication (HS256): register, login, logout endpoints
- Stripe integration: Checkout session creation, webhook event processing for payment confirmation
- Resend email integration: transactional emails for booking confirmation and cancellation
- Full-text search (FTS5) on venue and plan names via `q` query parameter
- Rate limiting middleware (token-bucket per IP) to protect public endpoints
- Prometheus-compatible metrics endpoint (`GET /metrics`)
- Waitlist support: bookings created when capacity is exhausted are queued automatically
- Audit log: all mutating admin actions recorded to `audit_logs` table with actor, IP, and timestamp

[Unreleased]: https://github.com/yukihamada/asoview-c/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/yukihamada/asoview-c/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/yukihamada/asoview-c/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/yukihamada/asoview-c/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yukihamada/asoview-c/releases/tag/v0.1.0
