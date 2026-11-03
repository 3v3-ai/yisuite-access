# yisuite-access

One way for every Yisuite app to decide who may do what. **Eve decides** (who the person is, which
organization they act for, what that organization's plan allows, which workspaces they may open);
**the app enforces** it, the same way in every app, with a few lines instead of its own login,
user table and role table.

| Piece | Python (`python/`) | Node (`node/`) |
| --- | --- | --- |
| Verify Eve's RS256 tokens against Eve's public keys (JWKS) | `TokenVerifier` | `remoteVerifier` |
| The six-check decision with stable refusal codes | `decide` | `decide` |
| Ask Eve for the person's access (cached; stale if Eve is down, never "allow") | `AccessCore` | `YisuiteAccess` |
| Default-deny gate + `require(feature, workspace)` | Flask `YisuiteAccess`, FastAPI `YisuiteAccessFastAPI` | Express `YisuiteAccess` |
| Eve's signed change events, applied once | `/_yisuite/events` | `/_yisuite/events` |
| One-time hand-off code into a session | `/_yisuite/handoff` | `/_yisuite/handoff` |
| Conformance personas | `conformance.run` | (contract replay) |

## What an app declares (an `AppModel`)

Its feature keys, which plan bundle owns each, what each plan includes, what each role grants, and
what counts as a write or an export. Nothing about login, orgs, plans' prices or users.

```python
class MyModel:
    def bundle_for_key(self, key): ...        # 'core' | 'ai' | PLATFORM | None (None = closed)
    def plan_bundles(self, plan_key): ...     # {'core', 'banking'} or None when the plan is unknown
    def role_keys(self, role): ...            # feature keys the role grants
    def default_role(self, org_role): ...     # role for an org owner/admin/member
    def is_write(self, method, path): ...
    def is_export(self, path): ...
```
Rules that are only prefixes and lists can use `TableModel` (same table in both languages).

## The decision

1 caller, 2 org, 3 plan (Eve's `ent` claim when present: the company's bundles, added / removed keys, limits,
`live` / `read_only` / `locked`; else the plan key through `AppModel.plan_bundles`), 4 workspace, 5 state (ready open,
suspended read-only, others hidden), 6 feature (role keys, level: viewer = read-only). The first
refusal wins; anything unknown (plan, status, key) is refused and named `UNKNOWN_<THING>`.
Codes: `NO_CALLER NO_ORG NO_APP_ACCESS ORG_READ_ONLY ORG_LOCKED PLAN_FEATURE SEAT_LIMIT
QUOTA_EXCEEDED NO_WORKSPACE_ACCESS WORKSPACE_READ_ONLY WORKSPACE_UNAVAILABLE FEATURE_ACCESS_DENIED`.
Every refusal body: `{success:false, error, error_code, next_action, subscribe_url?}`.

## Entitlements (no plan names in apps)

Eve resolves what each company may use per app (plan + add-ons + company overrides) and sends it in the
token as `ent: {<app>: {b, add, rm, lim, cat, st}}` with `entv: 1`. The SDK reads the audience app's entry
(`ent_from_claims` / `entFromClaims`) and step 3 answers from it alone; `plan_bundles` is then never called.

| Python | Node | Answers |
| --- | --- | --- |
| `org_allows(ent, key, model)` | `orgAllows(ent, key, model)` | is the company entitled to the key (capabilities such as multi-currency) |
| `org_limit(ent, key)` | `orgLimit(ent, key)` | the quota, `None`/`null` = unlimited |
| `quota_refusal(ent, key, used)` | `quotaRefusal(ent, key, used)` | `QUOTA_EXCEEDED` with `limit`, `used`, `allowed` when a create would pass it |

`bundle_for_key` still names each key's default bundle: it is what the app publishes to Eve
(`PUT /api/access/catalog`), where admins may move keys between bundles and edit plans.

## Use

```python
# Flask
access = YisuiteAccess(app_slug='yiflow', eve_url='https://api.3v3.ai', client_secret=..., webhook_secret=..., model=MyModel())
access.init_app(app)                                   # needs app.secret_key
@app.get('/tickets')
@access.require(feature='tickets.list', workspace=lambda: request.args['company'])
def tickets(): ...

# FastAPI
access = YisuiteAccessFastAPI(..., public=['/health']); access.install(app)
@app.get('/jobs')
def jobs(d=Depends(access.require('jobs.list', workspace=lambda r: r.query_params.get('company')))): ...
```
```ts
// Express
const access = new YisuiteAccess({ appSlug: 'yimport', eveUrl, clientSecret, webhookSecret, model, public: ['/health'] });
app.use(access.routes()); app.use(access.gate());
app.get('/jobs', access.require({ feature: 'jobs.list', workspace: req => String(req.query.company) }), handler);
```

## Tests and the shared contract

- `contracts/key_cover_cases.json`: the key-matching vectors (also run by Yincome's pytest and vitest).
- `contracts/decision_cases.json`: 1,152 cases **generated from the Python decision** (the reference).
  The Node tests replay it and must decide identically. After changing a rule: edit Python, run
  `python python/scripts/gen_decision_cases.py`, port the change to `node/src/decision.ts`, commit all three.
- Each app runs `conformance.run(MyModel(), ...)` in its own CI: twelve personas, and it catches a model
  that ignores the plan or lets viewers write.

Run: `cd python && pip install -e '.[flask,test]' fastapi httpx && pytest` / `cd node && npm i && npm test`.

## Registering an app (once, in Eve)

`npm run access-admin -- client create <name> <app> access:read,handoff:redeem,workspace:write` (secret shown
once; the app's `EVE_SERVICE_CLIENT_SECRET`), `... app register <app> --webhook <url> --handoff code --kind <workspace kind>`
(prints the app's `YISUITE_WEBHOOK_SECRET`).
