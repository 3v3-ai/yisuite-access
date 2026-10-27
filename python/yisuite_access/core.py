"""The framework-neutral part of the adapters: who is this, what does Eve say, decide, events.

Flask and FastAPI adapters are thin: they pull the token and the request facts out of their
framework and call this.
"""

from __future__ import annotations

import time
from typing import Optional

from . import reasons
from .client import EveClient, EveUnavailable
from .decision import AppModel, Decision, Person, WorkspaceAccess, decide
from .events import Dedupe, signature_ok
from .reasons import Refusal
from .tokens import TokenVerifier, lapsed_since_from_document, person_from_claims


class AccessCore:
    def __init__(self, app_slug: str, eve_url: str, model: AppModel, client_secret: str = '', webhook_secret: str = '',
                 issuer: str = 'https://api.3v3.ai', subscribe_url: Optional[str] = 'https://www.3v3.ai/billing',
                 verifier=None, client=None, doc_ttl: float = 30.0, stale_ok: float = 600.0):
        self.app_slug, self.model = app_slug, model
        self.verifier = verifier or TokenVerifier(app_slug, f'{eve_url.rstrip("/")}/.well-known/jwks.json', issuer)
        self.client = client or EveClient(eve_url, client_secret)
        self.webhook_secret, self.subscribe_url = webhook_secret, subscribe_url
        self.dedupe = Dedupe()
        self.docs: dict = {}
        self.doc_ttl, self.stale_ok = doc_ttl, stale_ok

    def person(self, token: Optional[str]) -> Optional[Person]:
        if not token:
            return None
        try:
            return person_from_claims(self.verifier.verify(token))
        except Exception:
            return None

    def document(self, person: Person) -> Optional[dict]:
        """Eve's access document for the person: cached briefly; the last answer is served for a
        while if Eve is unreachable (never wider than what they had); then it raises."""
        key = (person.user_id, person.org_id)
        now = time.monotonic()
        hit = self.docs.get(key)
        if hit and now - hit[0] < self.doc_ttl:
            return hit[1]
        try:
            doc = self.client.access_for(person.user_id, person.org_id)
        except EveUnavailable:
            if hit and now - hit[0] < self.stale_ok:
                return hit[1]
            raise
        self.docs[key] = (now, doc)
        return doc

    @staticmethod
    def find_workspace(doc: dict, key: Optional[str]) -> Optional[WorkspaceAccess]:
        if not key:
            return None
        for w in (doc or {}).get('workspaces') or []:
            if str(w.get('key')).lower() == str(key).lower():
                return WorkspaceAccess(key=w['key'], level=w.get('level') or 'editor', status=w.get('status') or 'ready',
                                       app_role=w.get('app_role'), data_window=w.get('data_window'))
        return None

    def decide(self, person: Optional[Person], keys, method: str, path: str, workspace_key: Optional[str] = None,
               workspace_required: bool = True) -> Decision:
        if person is None:
            return decide(None, None, keys, method, path, self.model)
        try:
            doc = self.document(person) or {}
        except EveUnavailable:
            return Decision.no(Refusal(reasons.NO_CALLER, 503, 'Access could not be checked right now.', 'Try again shortly.'))
        person = Person(**{**person.__dict__, 'plan_lapsed_since': lapsed_since_from_document(doc)})
        return decide(person, self.find_workspace(doc, workspace_key), keys, method, path, self.model,
                      workspace_required=workspace_required, subscribe_url=self.subscribe_url)

    def handle_event(self, body: bytes, signature: str, data: dict) -> str:
        """'unauthorized' | 'duplicate' | 'applied'."""
        if not signature_ok(self.webhook_secret, body, signature):
            return 'unauthorized'
        if not self.dedupe.first_time(data.get('id')):
            return 'duplicate'
        self.docs.clear()                       # something about someone changed: ask Eve again
        return 'applied'

    def redeem(self, code: str):
        """(http_status, body, token_or_None)."""
        if not code:
            return 400, {'success': False, 'error': 'code is required'}, None
        try:
            out = self.client.redeem(code)
        except EveUnavailable as e:
            return 503, {'success': False, 'error_code': 'EVE_UNAVAILABLE', 'error': str(e)}, None
        if not out or not out.get('token'):
            return 401, {'success': False, 'error_code': 'HANDOFF_REFUSED',
                         'error': 'The sign-in link was already used or has expired. Open the app again from 3v3.'}, None
        return 200, {'success': True}, out['token']
