# Moving each app onto the SDK

Not done yet for any app: each move changes how that app signs people in, so each needs its owner to
review and a staged switch (SDK beside the old auth, both logging, then the old path removed).
Prerequisites for all: Eve phase 2 deployed (Eve PR #64), a service client and webhook registered for the app
(see README), `EVE_SERVICE_CLIENT_SECRET` and `YISUITE_WEBHOOK_SECRET` in the app's environment AND named in
its compose file's `environment:` list (a variable only in `.env` never reaches the container).

| App | Adapter | Today | Steps | Removes |
| --- | --- | --- | --- | --- |
| **Yincome** | (reference: `services/access`) | own decorator, v2 tokens + `ACCESS_SOURCE` already built | Deploy; `EVE_TOKEN_MODE=both`, `ACCESS_SOURCE=shadow` a week, then `eve`; `VITE_EVE_TOKEN_V2=true`; backfill (`scripts/backfill_access_to_eve.py`); then `v2` | `JWT_SECRET` use, local grant tables as the source |
| **Yingdom** (Flask) | Flask | `iam.py` decodes HS256, `plans.cloudprofit`, asks Yincome `my-databases`; PIN login | Replace `iam.py`'s decode and `my-databases` call with `YisuiteAccess(workspace via Yincome's workspaces)`; roles from Eve's `org_role`/platform role | `AUTH_MODE=local`, users table, PIN columns, `/api/iam/*` proxy |
| **Yi.Flow** (Flask) | Flask | `?auth_token` HS256, local users must exist, 5 local roles, `user_companies` | Each client company becomes a workspace (app `yiflow`) owned by its org; the 5 roles become Yi.Flow app roles in `AppModel`; handoff via `/_yisuite/handoff` | hardcoded `ying@et-management.com` manager, fuzzy staff matching, `/dev-login`, intake shared token (becomes a service client) |
| **YInvoice** (FastAPI) | FastAPI | flat `plan` claim, per-user tenancy, `INTERNAL_ROLES` | One workspace per org to start; internal staff via platform `support` role | `SKIP_AUTH`, `SECRET_KEY` fallback, `auth_postgres.py` |
| **Evelens** (FastAPI) | FastAPI | same as YInvoice, cookie-only | same as YInvoice | default secret |
| **Yimport** (FastAPI) | FastAPI | Cloudflare Access only; one static Yincome token | SDK login for platform-org members (Cloudflare may stay as an outer wall); call Yincome as service client `yimport` scoped to the workspaces it imports into | `YINCOME_TOKEN`, the `CF_ACCESS_ENABLED=false` path |
| **Eve dashboard** | n/a | tiles from per-user grants; org plans ignored | tiles from each app's plan state in `/api/access/me` | `app_permissions`, `app_role_permissions`, `app_denies` after the move |

Retire last: `JWT_SECRET` in every app, Eve's HS256 issuer and `/api/auth/verify` (after 30 days of no calls).
