# yisuite-access ↔ Eve: the calls (v0.1.0)

Base: `EVE_API_URL` (default `https://api.3v3.ai`). Every call sends
`Authorization: Bearer <EVE_SERVICE_CLIENT_SECRET>` and `User-Agent: yisuite-access/<ver> (<app>)`
(Cloudflare on api.3v3.ai blocks `Python-urllib/*`). Timeout 8 s. A connection error, 429 or 5xx
is retried twice (0.5 s, 1 s); a 4xx is not. Writes carry an idempotency key, so a retry never
double-counts. Without a secret the four reporting calls are a no-op (return `None`); the reads
raise `EveUnavailable`, which never means "allow".

| Python (`EveClient`) | HTTP | Scope | Idempotent by |
|---|---|---|---|
| `publish_catalog(catalog)` | `PUT /api/access/catalog` | `catalog:write` | content hash (Eve) |
| `notify(type, title, target, severity, company, body, link, payload, dedupe_key)` | `POST /api/notify/events` | `notify:write` | `dedupe_key` (generated if absent; repeat → `duplicate: true`, 200) |
| `report_usage(tenant, [{event_id, limit, quantity, occurred_at?}])` | `POST /api/access/usage` | `usage:write` | `(app, event_id)`; same id with other company/limit/quantity → `rejected` |
| `read_usage(tenant, at=None)` | `GET /api/access/usage/:tenant` | `access:read` | read |
| `health_event(kind, ok, detail, event_id, counts)` | `POST /api/access/suite-events` | `access:read` (Eve has no separate health scope) | `event_id` |
| `access_for(user_id, org_id)` | `GET /api/access/users/:id` | `access:read` | read |
| `redeem(code)` | `POST /api/handoff/redeem` | — | single-use code; never retried |

`notify` target: `{"user_ids": [..]}` or `{"emails": [..]}` or `{"company_roles": [..]}`.
`health_event` counts: `[{"kind": "signin"|"guard_refusal", "label": "...", "count": n}]`.
Use a key derived from your own record (`f"doc-{id}-approved"`) for `dedupe_key` / `event_id`
when the same business event can be reported twice; the generated key only protects retries.

Removed in 0.1.0: `report_workspace` (`PUT /api/access/workspaces`, retired in Eve).

## Tokens

`EnvVerifier(app_slug)` / `TokenVerifier(app_slug, jwks_url)`: RS256 only, keys from
`<EVE_API_URL>/.well-known/jwks.json` (cached 10 min, refetched on an unknown kid), required
`exp iat sub aud iss`, `aud` = app slug, `iss` = `https://api.3v3.ai`. `ent` is read only when
`entv == 1`, keyed by the audience. `tid` and `org.{id,role}` are parsed into `EveClaims`.

`EVE_TOKEN_MODE`: `off` (default, also unset/unknown) · `both` (token beside the old sign-in) ·
`v2` (token is the only sign-in; the app's adapter refuses the old path). `EnvVerifier.enabled()`
is true for `both` and `v2`.

## Conformance

`yisuite_access.token_conformance.make_tests(audience, verify)` gives pytest tests an app runs
in CI against its own verification path: good token, wrong audience, wrong issuer, expired,
unknown kid, other key, HS256, no `exp`, no `ent`, unknown `entv`.
`yisuite_access.conformance.run(model, ...)` covers access decisions (twelve personas).
