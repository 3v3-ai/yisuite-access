"""An app calling Eve as a registered service client."""

from __future__ import annotations

from typing import Optional


class EveUnavailable(Exception):
    """Eve could not be reached or refused this app's credential. Never means 'allow'."""


class EveClient:
    def __init__(self, eve_url: str, secret: str, timeout: float = 8.0, http=None):
        self.base = eve_url.rstrip('/')
        self.secret = secret
        self.timeout = timeout
        self._http = http

    def _request(self, method: str, path: str, **kw):
        if not self.secret:
            raise EveUnavailable('no service-client secret configured')
        import requests
        http = self._http or requests
        try:
            return http.request(method, self.base + path, timeout=self.timeout,
                                headers={'Authorization': f'Bearer {self.secret}'}, **kw)
        except requests.RequestException as e:
            raise EveUnavailable(f'Eve unreachable: {e}') from e

    def access_for(self, user_id: int, org_id: Optional[int] = None) -> Optional[dict]:
        r = self._request('GET', f'/api/access/users/{int(user_id)}', params={'org_id': org_id} if org_id else None)
        if r.status_code == 404:
            return None
        if r.status_code >= 400:
            raise EveUnavailable(f'Eve answered {r.status_code}')
        return r.json()

    def redeem(self, code: str) -> Optional[dict]:
        r = self._request('POST', '/api/handoff/redeem', json={'code': code})
        if r.status_code in (400, 401):
            return None
        if r.status_code >= 400:
            raise EveUnavailable(f'Eve answered {r.status_code}')
        return r.json()

    def report_workspace(self, key: str, name=None, status=None, org_id=None) -> bool:
        body = {k: v for k, v in {'key': key, 'name': name, 'status': status, 'org_id': org_id}.items() if v is not None}
        return self._request('PUT', '/api/access/workspaces', json=body).status_code < 300
