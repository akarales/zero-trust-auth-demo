# API Reference

Base URL: `http://localhost:8011`.

## Health

```bash
curl localhost:8011/health
```

```json
{ "status": "ok", "version": "0.1.0" }
```

## Issue a token (demo IdP)

```bash
curl -X POST localhost:8011/auth/token -H 'content-type: application/json' \
  -d '{"user":"ada","role":"physician","department":"cardiology"}'
```

```json
{ "token": "eyJhbGciOiJIUzI1NiIs…", "expires_in": 3600 }
```

Claims carry the ABAC attributes: `sub`, `role`, `department`, `iat`,
`exp`. Roles used by policy: `physician`, `nurse`, `auditor`, `admin`.

## Protected records

```bash
TOKEN=…   # the physician token above
curl localhost:8011/api/v1/records/cardio-patient-1 \
  -H "Authorization: Bearer $TOKEN"
```

```json
{ "record_id": "cardio-patient-1", "department": "cardiology",
  "content": "Cardiology record: synthetic" }
```

Record ids encode the owning department (`cardio-*` → cardiology,
`onco-*` → oncology). Actions:

- `GET` — read (physicians + nurses of the department)
- `PUT {"content": "…"}` — write (physicians only)
- `PATCH` — approve (physicians only)

## Audit tail

```bash
AUDITOR=…   # {"user":"zed","role":"auditor","department":"security"}
curl localhost:8011/api/v1/audit -H "Authorization: Bearer $AUDITOR"
```

Auditors-only by rule R1 — a physician token gets `403` here even with
a valid JWT.

## Error taxonomy

| Status | Meaning |
|--------|---------|
| `401` | missing bearer token / invalid or expired token |
| `403` | policy denied (cross-department, wrong role, wrong resource kind) |
| `404` | unknown record id |
| `429` | rate limit exceeded (per-subject bucket) |

Every response — 2xx or error — leaves an audit record.
