"""Flask adapter: login, default-deny, the decision, events, hand-off, in a few lines.

    access = YisuiteAccess(app_slug='yiflow', eve_url=..., client_secret=..., webhook_secret=..., model=MyModel())
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

from functools import wraps
from typing import Callable, Optional

from . import reasons
from .core import AccessCore
from .decision import AppModel, Decision, Person
from .reasons import Refusal

GUARD = '_ys_guard'
SESSION_KEY = 'ys_token'


class YisuiteAccess(AccessCore):
    def __init__(self, *args, login_url: str = 'https://www.3v3.ai/login', **kwargs):
        super().__init__(*args, **kwargs)
        self.login_url = login_url
        self._public_paths = {'/_yisuite/handoff', '/_yisuite/events', '/_yisuite/logout'}

    def _token(self):
        from flask import request, session
        h = request.headers.get('Authorization', '')
        return h[7:].strip() if h.startswith('Bearer ') else session.get(SESSION_KEY)

    def current_person(self) -> Optional[Person]:
        from flask import g
        if not hasattr(g, '_ys_person'):
            g._ys_person = self.person(self._token())
        return g._ys_person

    def decide_here(self, feature_keys, workspace_key=None, workspace_required=True) -> Decision:
        from flask import request
        return self.decide(self.current_person(), list(feature_keys), request.method, request.path,
                           workspace_key, workspace_required)

    def public(self, reason: str):
        def deco(fn):
            fn._ys_public = reason
            return fn
        return deco

    def require(self, feature, workspace: Optional[Callable[[], Optional[str]]] = None, level: Optional[str] = None):
        keys = [feature] if isinstance(feature, str) else list(feature)

        def deco(fn):
            @wraps(fn)
            def wrapper(*a, **kw):
                from flask import g
                d = self.decide_here(keys, workspace() if workspace else None, workspace_required=workspace is not None)
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
            if self.current_person() is None:                # undecorated: a signed-in person at least
                return self._refuse(Refusal(reasons.NO_CALLER, 401, 'Sign in to continue.', 'Sign in.'))
            return None

        @app.post('/_yisuite/handoff')
        def handoff():
            status, body, token = self.redeem(str((request.get_json(silent=True) or {}).get('code') or '').strip())
            if token:
                session[SESSION_KEY] = token
            return jsonify(body), status

        @app.post('/_yisuite/events')
        def events():
            out = self.handle_event(request.get_data(), request.headers.get('X-Yisuite-Signature', ''),
                                    request.get_json(silent=True) or {})
            if out == 'unauthorized':
                return jsonify({'success': False, 'error': 'Unauthorized'}), 401
            return jsonify({'success': True, **({'duplicate': True} if out == 'duplicate' else {})}), 200

        @app.post('/_yisuite/logout')
        def logout():
            session.pop(SESSION_KEY, None)
            return jsonify({'success': True}), 200
