"""FastAPI adapter. Same behaviour as the Flask and Express adapters.

    access = YisuiteAccessFastAPI(app_slug='yimport', eve_url=..., client_secret=..., webhook_secret=...,
                                  model=MyModel(), public=['/health'])
    access.install(app)            # gate middleware, /_yisuite/* routes, JSON refusals

    @app.get('/jobs')
    def jobs(d = Depends(access.require('jobs.list', workspace=lambda r: r.query_params.get('company')))): ...

The gate refuses every path that is not listed in `public` unless a verified person is
signed in; require() adds the decision. A route is never open by default.
"""

from __future__ import annotations

import json
from typing import Callable, Iterable, Optional

from fastapi import Request                      # module level: FastAPI resolves route annotations from here
from fastapi.responses import JSONResponse, RedirectResponse

from . import reasons
from .core import AccessCore
from .decision import Decision
from .reasons import Refusal

COOKIE = 'ys_token'


class Refused(Exception):
    def __init__(self, refusal: Refusal):
        self.refusal = refusal


class YisuiteAccessFastAPI(AccessCore):
    def __init__(self, *args, public: Iterable = (), login_url: str = 'https://www.3v3.ai/login',
                 secure_cookie: bool = True, **kwargs):
        super().__init__(*args, **kwargs)
        self.public = list(public) + ['/_yisuite/handoff', '/_yisuite/events', '/_yisuite/logout']
        self.login_url, self.secure_cookie = login_url, secure_cookie

    def _is_public(self, path: str) -> bool:
        return any((p == path) if isinstance(p, str) else bool(p.search(path)) for p in self.public)

    def _token(self, request) -> Optional[str]:
        h = request.headers.get('authorization', '')
        return h[7:].strip() if h.startswith('Bearer ') else request.cookies.get(COOKIE)

    def _person(self, request):
        if not hasattr(request.state, 'ys_person'):
            request.state.ys_person = self.person(self._token(request))
        return request.state.ys_person

    def require(self, feature, workspace: Optional[Callable] = None):
        """A dependency: returns the Decision, or refuses with the standard body."""
        keys = [feature] if isinstance(feature, str) else list(feature)

        async def dependency(request):                                      # FastAPI injects Request by annotation below
            ws = workspace(request) if workspace else None
            d: Decision = self.decide(self._person(request), keys, request.method, request.url.path, ws,
                                      workspace_required=workspace is not None)
            if not d.allowed:
                raise Refused(d.refusal)
            request.state.ys_decision = d
            return d

        dependency.__annotations__['request'] = Request
        return dependency

    def install(self, app) -> None:
        def body(refusal: Refusal, request: Request):
            if refusal.status == 401 and request.method == 'GET' and 'text/html' in request.headers.get('accept', ''):
                return RedirectResponse(self.login_url, status_code=302)
            return JSONResponse(refusal.body(), status_code=refusal.status)

        @app.exception_handler(Refused)
        async def refused(request: Request, exc: Refused):
            return body(exc.refusal, request)

        @app.middleware('http')
        async def gate(request: Request, call_next):
            if request.method == 'OPTIONS' or self._is_public(request.url.path):
                return await call_next(request)
            if self._person(request) is None:
                return body(Refusal(reasons.NO_CALLER, 401, 'Sign in to continue.', 'Sign in.'), request)
            return await call_next(request)

        @app.post('/_yisuite/handoff')
        async def handoff(request: Request):
            try:
                data = await request.json()
            except Exception:
                data = {}
            status, payload, token = self.redeem(str((data or {}).get('code') or '').strip())
            resp = JSONResponse(payload, status_code=status)
            if token:
                resp.set_cookie(COOKIE, token, httponly=True, samesite='lax', secure=self.secure_cookie, max_age=900)
            return resp

        @app.post('/_yisuite/events')
        async def events(request: Request):
            raw = await request.body()
            try:
                data = json.loads(raw or b'{}')
            except ValueError:
                data = {}
            out = self.handle_event(raw, request.headers.get('x-yisuite-signature', ''), data)
            if out == 'unauthorized':
                return JSONResponse({'success': False, 'error': 'Unauthorized'}, status_code=401)
            return JSONResponse({'success': True, **({'duplicate': True} if out == 'duplicate' else {})})

        @app.post('/_yisuite/logout')
        async def logout():
            resp = JSONResponse({'success': True})
            resp.delete_cookie(COOKIE)
            return resp
