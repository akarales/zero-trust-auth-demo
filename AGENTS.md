# AGENTS.md

## Commands

```bash
cargo run                  # :8011
cargo test -q              # 20 tests (12 unit + 8 flow)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Environment

`APP_PORT` (8011) · demo JWT secret is compiled for the demo — swap for
an env-provided secret before any real use

## Conventions

- Conventional commits; hygiene hook strips AI attribution
- Policy rules live in `src/policy.rs` as ordered pure functions —
  change rules AND tests together; default deny is never removed
- jsonwebtoken 11: HS256 keys must be ≥ 32 bytes (it panics otherwise)
  and a crypto provider feature is required (rust_crypto)
- Deps ≥7 days old (BEST_PRACTICES/INDEX.md)
