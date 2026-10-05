# Development Guide

Machine-facing commands live in [AGENTS.md](../AGENTS.md).

## Prerequisites

Rust 1.96, cargo. Nothing else — no Redis, no Postgres at this stage.

## Daily loop

```bash
cargo run           # :8011
cargo test -q      # 20 tests — 12 unit + 8 flow
cargo clippy --all-targets -- -D warnings
```

## Testing notes

- **Policy tests** pin the rulebook: same-department allow, cross-
  department deny, nurse read-only, audit isolation, admin separation,
  unknown-role denial
- **Flow tests** drive the full pipeline over the real router: token
  issue → protected reads/writes → 401 (no/garbage token) → 403
  (cross-department, audit as physician) → 429 (tight bucket: 2
  capacity, zero refill)
- Stateful sequences use ONE router instance (clone per request)

## Changing policy safely

Policy changes are behavior changes with a paper trail:

1. Edit the ordered rules in `src/policy.rs` (keep the doc table in sync)
2. Add/adjust the unit test that pins the new behavior
3. Never remove the deny-by-default fallthrough — it is the security
   property, and a test exists to keep it

## Gotchas learned here

- **jsonwebtoken 11**: needs the `rust_crypto` feature, and it **panics**
  on HS256 keys shorter than the RFC minimum — use 32-byte secrets
  (that's why the test keys look like hex blobs)
- **CI clippy is newer than local stable**: `Result<_, axum::Response>`
  tripped `result_large_err` on 1.99; the error payload is `Box`ed
- Port 8011

## Conventions

Conventional commits; hygiene hook strips AI attribution. The demo JWT
secret is compiled in for the demo — env-provide it (`APP_JWT_SECRET`)
before anything real.
