# Architecture

## Modules

```
src/
├── auth.rs        # JWT issue/verify (HS256, ≥32-byte keys)
├── policy.rs      # ABAC rules as ordered pure functions (6 unit tests)
├── rate_limit.rs  # per-subject token bucket (3 unit tests)
├── audit.rs       # append-only JSONL (file or tracing)
├── routes.rs      # the request pipeline
└── state.rs       # demo secret, limiter, audit, records
```

## The policy rulebook (src/policy.rs)

Attributes — not bare roles — decide. Subject (role, department),
action, resource (kind, owning department). Ordered rules, first match
wins, **deny by default**:

| # | Rule | Effect |
|---|------|--------|
| R1 | Audit log: auditors may read; nobody may write | contains the blast radius of tampering |
| R2 | System config: admin only | separation of duty |
| R3 | Patient records: same-department physicians/nurses read; physicians write/approve | least privilege + ownership |

Tests pin every rule: same-department physician reads; cross-department
denied; nurses read but never write or approve; audit isolation (even a
"security-department physician" can't read the log); admin separation;
unknown roles denied everywhere.

## The request pipeline (src/routes.rs)

Every protected endpoint runs the same four stages, in order:

1. **Authenticate** — Bearer token → `verify` → typed claims (no token
   or garbage → `401`)
2. **Rate limit** — one token-bucket consumption per subject per
   request (`429` when empty)
3. **Authorize** — `decide()` over the claims' attributes and the
   resource (`403` on deny)
4. **Audit** — one JSONL record per request: subject, role, action,
   resource, decision (including rate-limit denials), request id

The audit record is written for EVERY decision — including denials.
`Box<Response>` for the authz error payload (newer CI clippy flags
`result_large_err`; local 1.96 didn't — documented gotcha).

## Rate limiter (src/rate_limit.rs)

Per-subject token bucket: capacity + refill/second, `Arc<Mutex<HashMap>>`
buckets. Tests pin the three behaviors that matter: bursts are limited,
clients are isolated, refills restore capacity. Redis backing is Phase 1
(the interface is a value type; the swap is mechanical).

## Design decisions

| Decision | Why |
|----------|-----|
| ABAC over RBAC | Roles alone can't express "same department" — the attribute that matters for records |
| Deny by default, tested | The default is load-bearing; a test asserts unknown roles get nothing |
| Audit-everything (even denials) | A zero-trust audit trail that only records successes isn't one |
| Policy as code, ordered rules | Reads like a policy file; changes ship with tests |
