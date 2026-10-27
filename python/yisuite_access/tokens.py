"""Verify Eve's v2 access tokens: RS256, one audience, public keys from Eve's JWKS.

The app holds nothing that could forge a token. Issuer, audience and expiry are enforced.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .decision import Person

DEFAULT_ISSUER = 'https://api.3v3.ai'


class TokenVerifier:
    def __init__(self, app_slug: str, jwks_url: str, issuer: str = DEFAULT_ISSUER, jwk_client=None):
        import jwt
        self.app_slug, self.issuer = app_slug, issuer
        self._client = jwk_client or jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=600)

    def verify(self, token: str) -> dict:
        """The verified claims, or jwt.PyJWTError."""
        import jwt
        key = self._client.get_signing_key_from_jwt(token).key
        return jwt.decode(token, key, algorithms=['RS256'], audience=self.app_slug, issuer=self.issuer,
                          options={'require': ['exp', 'iat', 'sub', 'aud', 'iss']})


def person_from_claims(claims: dict, lapsed_since: Optional[datetime] = None) -> Person:
    org = claims.get('org') or {}
    plan = claims.get('plan') or {}
    return Person(user_id=int(claims['sub']), email=claims.get('email') or '',
                  platform_role=claims.get('plat'), org_id=org.get('id'), org_type=org.get('type'),
                  org_role=org.get('role'), plan_key=plan.get('key'), plan_status=plan.get('status'),
                  plan_lapsed_since=lapsed_since)


def lapsed_since_from_document(doc: dict) -> Optional[datetime]:
    """When the org's plan lapsed, from Eve's access document (plan.ends_at)."""
    raw = ((doc or {}).get('plan') or {}).get('ends_at')
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace('Z', '+00:00')).astimezone(timezone.utc)
    except ValueError:
        return None
