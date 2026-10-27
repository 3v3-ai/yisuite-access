"""Flask adapter: login, default-deny, the decision, events, hand-off, in a few lines.

    access = YisuiteAccess(app_slug='yiflow', eve_url=..., client_secret=..., webhook_secret=...,
                           model=MyModel())
    access.init_app(app)           # needs app.secret_key

    @app.get('/tickets')
    @access.require(feature='tickets.list', workspace=lambda: request.args['company'])
    def tickets(): ...

    @app.get('/health')
    @access.public(reason='liveness probe')
    def health(): ...

Every route that is neither public nor decorated still needs a signed-in person (the gate
refuses anonymous callers); a route is never open by default.
"""

from __future__ import annotations

import time
from typing import Callable, Iterable, Optional

from .client import EveClient, EveUnavailable
from .decision import AppModel, Decision, Person, WorkspaceAccess, decide
from .events import Dedupe, signature_ok
from .reasons import Refusal
from . import reasons
from .tokens import TokenVerifier, lapsed_since_from_document, person_from_claims

GUARD = '_ys_guard'
SESSION_KEY = 'ys_token'


class YisuiteAccess:
    def __init__(self, app_slug: str, eve_url: str, model: AppModel, client_secret: str = '',
                 webhook_secret: str = '', issuer: str = 'https://api.3v3.ai', login_url: str = 'https://www.3v3.ai/login',
                 subscribe_url: Optional[str] = 'https://www.3v3.ai/billing', verifier=None, client=None,
                 doc_ttl: float = 30.0, stale_ok: float = 600.0):
        self.app_slug, self.model = app_slug, model
        self.verifier = verifier or TokenVerifier(app_slug, f'{eve_url.rstrip("/")}/.well-known/jwks.json', issuer)
        self.client = client or EveClient(eve_url, client_secret)
        self.webhook_secret, self.login_url, self.subscribe_url = webhook_secret, login_url, subscribe_url
        self._dedupe = Dedupe()
        self._docs: dict = {}
        self._doc_ttl, self._stale_ok = doc_ttl, stale_ok
        self._public_paths = {'/_yisuite/handoff', '/_yisuite/events'}

    # ── identity ────────────────────────────────────────────────────────────
    def _token(self):
        from flask import request, session
        h = request.headers.get('Authorization', '')
        return h[7:].strip() if h.startswith('Bearer ') else session.get(SESSION_KEY)

    def person(self) -> Optional[Person]:
        """The verified person for this request (cached on g), or None."""
        from flask import g
        if hasattr(g, '_ys_person'):
            return g._ys_person
        person = None
        token = self._token()
        if token:
            try:
                claims = self.verifier.verify(token)
                person = person_from_claims(claims)
            except Exception:
                person = None
        g._ys_person = person
        return person

    # ── Eve's document, cached, stale if Eve is down ────────────────────────
    def document(self, person: Person) -> Optional[dict]:
        key = (person.user_id, person.org_id)
        now = time.monotonic()
        hit = self._docs.get(key)
        if hit and now - hit[0] < self._doc_ttl:
            return hit[1]
        try:
            doc = self.client.access_for(person.user_id, person.org_id)
        except EveUnavailable:
            if hit and now - hit[0] < self._stale_ok:
                return hit[1]
            raise
        self._docs[key] = (now, doc)
        return doc

    def workspace(self, person: Person, key: Optional[str]) -> Optional[WorkspaceAccess]:
        if not key:
            return None
        doc = self.document(person) or {}
        for w in doc.get('workspaces') or []:
            if str(w.get('key')).lower() == str(key).lower():
                return WorkspaceAccess(key=w['key'], level=w.get('level') or 'editor', status=w.get('status') or 'ready',
                                       app_role=w.get('app_role'), data_window=w.get('data_window'))
        return None

    def decide(self, feature_keys, workspace_key=None, workspace_required=True) -> Decision:
        from flask import request
        person = self.person()
        if person is None:
            return decide(None, None, feature_keys, request.method, request.path, self.model)
        try:
            doc = self.document(person) or {}
            ws = self.workspace(person, workspace_key)
        except EveUnavailable:
            return Decision.no(Refusal(reasons.NO_CALLER, 503, 'Access could not be checked right now.', 'Try again shortly.'))
        person = Person(**{**person.__dict__, 'plan_lapsed_since': lapsed_since_from_document(doc)})
        return decide(person, ws, feature_keys, request.method, request.path, self.model,
                      workspace_required=workspace_required, subscribe_url=self.subscribe_url)

    # ── decorators ──────────────────────────────────────────────────────────
    def public(self, reason: str):
        def deco(fn):
            fn._ys_public = reason
            return fn
        return deco

    def require(self, feature, workspace: Optional[Callable[[], Optional[str]]] = None, level: Optional[str] = None):
        keys = [feature] if isinstance(feature, str) else list(feature)

        def deco(fn):
            from functools import wraps

            @wraps(fn)
            def wrapper(*a, **kw):
                from flask import g
                d = self.decide(keys, workspace() if workspace else None, workspace_required=workspace is not None)
                if not d.allowed:
                    return self._refuse(d.refusal)
                g.access = d
                return fn(*a, **kw)
            setattr(wrapper, GUARD, 'decided')
            return wrapper
        return deco

    def _refuse(self, refusal: Refusal):
        from flask import jsonify, redirect, request
        if refusal.status == 401 and 'text/html' in request.headers.get('Accept', '') and request.method == 'GET':
            return redirect(self.login_url)
        resp = jsonify(refusal.body())
        resp.status_code = refusal.status
        return resp

    # ── wiring ──────────────────────────────────────────────────────────────
    def init_app(self, app) -> None:
        from flask import jsonify, request, session

        @app.before_request
        def gate():
            if request.method == 'OPTIONS' or request.path in self._public_paths:
                return None
            view = app.view_functions.get(request.endpoint)
            if view is None:
                return None
            if getattr(view, '_ys_public', None) or getattr(view, GUARD, None):
                return None
            if self.person() is None:                        # undecorated: a signed-in person at least
                return self._refuse(Refusal(reasons.NO_CALLER, 401, 'Sign in to continue.', 'Sign in.'))
            return None

        @app.post('/_yisuite/handoff')
        def handoff():
            code = str((request.get_json(silent=True) or {}).get('code') or '').strip()
            if not code:
                return jsonify({'success': False, 'error': 'code is required'}), 400
            try:
                out = self.client.redeem(code)
            except EveUnavailable as e:
                return jsonify({'success': False, 'error_code': 'EVE_UNAVAILABLE', 'error': str(e)}), 503
            if not out or not out.get('token'):
                return jsonify({'success': False, 'error_code': 'HANDOFF_REFUSED',
                                'error': 'The sign-in link was already used or has expired. Open the app again from 3v3.'}), 401
            session[SESSION_KEY] = out['token']
            return jsonify({'success': True}), 200

        @app.post('/_yisuite/events')
        def events():
            if not signature_ok(self.webhook_secret, request.get_data(), request.headers.get('X-Yisuite-Signature', '')):
                return jsonify({'success': False, 'error': 'Unauthorized'}), 401
            data = request.get_json(silent=True) or {}
            if not self._dedupe.first_time(data.get('id')):
                return jsonify({'success': True, 'duplicate': True}), 200
            self._docs.clear()                              # something about someone changed: ask Eve again
            return jsonify({'success': True}), 200

        @app.post('/_yisuite/logout')
        def logout():
            session.pop(SESSION_KEY, None)
            return jsonify({'success': True}), 200
