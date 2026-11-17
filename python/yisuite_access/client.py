"""An app calling Eve (3v3) as a registered service client. The calls are in CONTRACT.md.

Every call has a timeout, retries a transient failure (connection error, 429, 5xx) with
backoff, and sends its own User-Agent (Cloudflare blocks Python-urllib's). Writes carry an
idempotency key Eve dedupes on, so a retry never double-counts.

Without a secret the reporting calls (publish_catalog, notify, report_usage, health_event)
are a no-op returning None: an app that is not registered yet keeps running. The reads that
an access decision depends on (access_for, redeem, read_usage) raise EveUnavailable instead,
which never means "allow".
"""

from __future__ import annotations

import time
import uuid
from typing import Iterable, Optional

RETRY_STATUS = {429, 500, 502, 503, 504}


class EveUnavailable(Exception):
    """Eve could not be reached or refused this app's credential. Never means 'allow'."""


def new_key(prefix: str = '') -> str:
    """A fresh idempotency key. Prefer a key derived from your own record id (stable across retries
    of the same business event, e.g. f'doc-{doc.id}-approved')."""
    return f'{prefix}{uuid.uuid4().hex}'


class EveClient:
    def __init__(self, eve_url: str, secret: str, timeout: float = 8.0, http=None, retries: int = 2,
                 backoff: float = 0.5, app_slug: str = 'app', sleep=time.sleep):
        self.base = eve_url.rstrip('/')
        self.secret = secret
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.app_slug = app_slug
        self._http = http
        self._sleep = sleep

    @property
    def configured(self) -> bool:
        return bool(self.secret)

    def _request(self, method: str, path: str, retry: bool = True, **kw):
        if not self.secret:
            raise EveUnavailable('no service-client secret configured')
        import requests
        from .tokens import user_agent
        http = self._http or requests
        headers = {'Authorization': f'Bearer {self.secret}', 'User-Agent': user_agent(self.app_slug),
                   **kw.pop('headers', {})}
        last = None
        tries = self.retries + 1 if retry else 1
        for attempt in range(tries):
            if attempt:
                self._sleep(self.backoff * (2 ** (attempt - 1)))
            try:
                r = http.request(method, self.base + path, timeout=self.timeout, headers=headers, **kw)
            except requests.RequestException as e:
                last = EveUnavailable(f'Eve unreachable: {e}')
                continue
            if r.status_code in RETRY_STATUS and attempt < tries - 1:
                last = EveUnavailable(f'Eve answered {r.status_code}')
                continue
            return r
        raise last

    @staticmethod
    def _ok(r):
        if r.status_code >= 400:
            raise EveUnavailable(f'Eve answered {r.status_code}')
        return r.json()

    # --- reads an access decision depends on --------------------------------------------------

    def access_for(self, user_id: int, org_id: Optional[int] = None) -> Optional[dict]:
        r = self._request('GET', f'/api/access/users/{int(user_id)}', params={'org_id': org_id} if org_id else None)
        if r.status_code == 404:
            return None
        return self._ok(r)

    def redeem(self, code: str) -> Optional[dict]:
        # a hand-off code is single-use: never retried
        r = self._request('POST', '/api/handoff/redeem', retry=False, json={'code': code})
        if r.status_code in (400, 401):
            return None
        return self._ok(r)

    def read_usage(self, tenant: str, at: Optional[str] = None) -> dict:
        """GET /api/access/usage/:tenant (scope access:read): this app's usage and limits for a company."""
        r = self._request('GET', f'/api/access/usage/{tenant}', params={'at': at} if at else None)
        return self._ok(r)

    # --- reporting (no-op without a secret) ---------------------------------------------------

    def publish_catalog(self, catalog: dict) -> Optional[dict]:
        """PUT /api/access/catalog (scope catalog:write). Idempotent by content: Eve hashes it."""
        if not self.configured:
            return None
        return self._ok(self._request('PUT', '/api/access/catalog', json=catalog))

    def notify(self, type: str, title: str, target: dict, severity: str = 'info', company: Optional[str] = None,
               body: Optional[str] = None, link: Optional[str] = None, payload: Optional[dict] = None,
               dedupe_key: Optional[str] = None) -> Optional[dict]:
        """POST /api/notify/events (scope notify:write). target = {user_ids|emails|company_roles}.
        dedupe_key makes it idempotent (a repeat answers duplicate: true); one is generated if absent."""
        if not self.configured:
            return None
        event = {'type': type, 'title': title, 'target': target, 'severity': severity,
                 'dedupe_key': dedupe_key or new_key('n-')}
        event.update({k: v for k, v in {'company': company, 'body': body, 'link': link, 'payload': payload}.items()
                      if v is not None})
        return self._ok(self._request('POST', '/api/notify/events', json=event))

    def report_usage(self, tenant: str, events: Iterable[dict]) -> Optional[dict]:
        """POST /api/access/usage (scope usage:write). Each event: {event_id, limit, quantity, occurred_at?};
        Eve dedupes on (app, event_id), so a missing event_id is filled with a fresh one."""
        if not self.configured:
            return None
        evs = [{**e, 'event_id': e.get('event_id') or new_key('u-')} for e in events]
        return self._ok(self._request('POST', '/api/access/usage', json={'tenant': tenant, 'events': evs}))

    def health_event(self, kind: str, ok: bool = True, detail: Optional[dict] = None,
                     event_id: Optional[str] = None, counts: Optional[list] = None) -> Optional[dict]:
        """POST /api/access/suite-events (scope access:read; Eve has no separate health scope).
        counts: [{kind: 'signin'|'guard_refusal', label, count}]."""
        if not self.configured:
            return None
        ev = {'kind': kind, 'ok': ok, 'event_id': event_id or new_key('h-')}
        if detail is not None:
            ev['detail'] = detail
        body = {'events': [ev]}
        if counts:
            body['counts'] = counts
        return self._ok(self._request('POST', '/api/access/suite-events', json=body))
