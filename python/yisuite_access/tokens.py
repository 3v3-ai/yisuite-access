"""Verify Eve's (3v3) v2 access tokens: RS256, one audience, public keys from Eve's JWKS.

The app holds nothing that could forge a token. Issuer, audience, expiry, iat and sub are
required. This is the one copy: the six hand-copied ``eve_token.py`` modules folded in here.

Two ways in:

* ``TokenVerifier(app_slug, jwks_url)``: explicit settings, used by the adapters.
* ``EnvVerifier(default_app_slug)``: reads the env at call time, the way every app copy did:

    EVE_TOKEN_MODE    off (default, also unset or unknown) | both | v2
                      both: a valid Bearer token is accepted beside the app's old sign-in
                      v2:   the token is the only sign-in (the app's adapter enforces that)
    EVE_API_URL       default https://api.3v3.ai
    EVE_JWKS_URL      default <EVE_API_URL>/.well-known/jwks.json
    EVE_TOKEN_ISSUER  default https://api.3v3.ai
    YISUITE_APP_SLUG  expected audience, default = the app's slug given in code

Errors: ``verify`` raises ``jwt.PyJWTError`` (``PyJWKClientError`` included: unknown kid,
JWKS unreachable). It never returns claims it did not check.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .decision import Person

DEFAULT_ISSUER = 'https://api.3v3.ai'
ENT_VERSION = 1
MODES = ('off', 'both', 'v2')
REQUIRED = ['exp', 'iat', 'sub', 'aud', 'iss']
JWKS_LIFESPAN = 600
JWKS_TIMEOUT = 8


def user_agent(app_slug: str) -> str:
    """Cloudflare in front of api.3v3.ai answers Python-urllib's default User-Agent with 403."""
    from . import __version__
    return f'yisuite-access/{__version__} ({app_slug})'


def make_jwk_client(jwks_url: str, app_slug: str):
    import jwt
    return jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=JWKS_LIFESPAN, timeout=JWKS_TIMEOUT,
                           headers={'User-Agent': user_agent(app_slug)})


def _decode(token: str, jwk_client, audience: str, issuer: str) -> dict:
    import jwt
    key = jwk_client.get_signing_key_from_jwt(token).key
    return jwt.decode(token, key, algorithms=['RS256'], audience=audience, issuer=issuer,
                      options={'require': REQUIRED})


class TokenVerifier:
    def __init__(self, app_slug: str, jwks_url: str, issuer: str = DEFAULT_ISSUER, jwk_client=None):
        self.app_slug, self.issuer = app_slug, issuer
        self._client = jwk_client or make_jwk_client(jwks_url, app_slug)

    def verify(self, token: str) -> dict:
        """The verified claims, or jwt.PyJWTError."""
        return _decode(token, self._client, self.app_slug, self.issuer)


@dataclass
class EveClaims:
    """What an app usually needs from a verified token. ``raw`` keeps every claim."""
    user_id: str
    email: str
    name: str = ''
    org_id: Optional[int] = None
    org_role: Optional[str] = None
    tid: Optional[str] = None
    ent: Optional[dict] = None
    raw: dict = field(default_factory=dict, repr=False)


def claims_to_eve(claims: dict) -> EveClaims:
    org = claims.get('org') if isinstance(claims.get('org'), dict) else {}
    tid = claims.get('tid')
    return EveClaims(user_id=str(claims['sub']), email=claims.get('email') or '',
                     name=claims.get('name') or '', org_id=org.get('id'), org_role=org.get('role'),
                     tid=str(tid) if tid not in (None, '') else None,
                     ent=ent_from_claims(claims), raw=claims)


def token_mode() -> str:
    m = (os.environ.get('EVE_TOKEN_MODE') or '').strip().lower()
    return m if m in MODES else 'off'


def bearer(header: Optional[str]) -> Optional[str]:
    """The token from an ``Authorization: Bearer <token>`` header, or None."""
    scheme, _, token = (header or '').partition(' ')
    token = token.strip()
    return token if scheme.lower() == 'bearer' and token else None


def looks_like_rs256(token: str) -> bool:
    """Unverified header peek, for routing only (an HS256 legacy token never triggers a JWKS fetch)."""
    import jwt
    try:
        return jwt.get_unverified_header(token).get('alg') == 'RS256'
    except jwt.PyJWTError:
        return False


class EnvVerifier:
    """Env-configured verifier (see module doc). Settings are read on every call, the JWKS
    client is rebuilt only when the JWKS URL changes."""

    def __init__(self, default_app_slug: str):
        self.default_app_slug = default_app_slug
        self._client = None
        self._client_url = ''

    def mode(self) -> str:
        return token_mode()

    def enabled(self) -> bool:
        return self.mode() in ('both', 'v2')

    def audience(self) -> str:
        return (os.environ.get('YISUITE_APP_SLUG') or self.default_app_slug).strip()

    def issuer(self) -> str:
        return (os.environ.get('EVE_TOKEN_ISSUER') or DEFAULT_ISSUER).strip()

    def jwks_url(self) -> str:
        explicit = (os.environ.get('EVE_JWKS_URL') or '').strip()
        if explicit:
            return explicit
        base = (os.environ.get('EVE_API_URL') or DEFAULT_ISSUER).strip().rstrip('/')
        return f'{base}/.well-known/jwks.json'

    def _get_client(self):
        url = self.jwks_url()
        if self._client is None or url != self._client_url:
            self._client = make_jwk_client(url, self.audience())
            self._client_url = url
        return self._client

    def verify_claims(self, token: str) -> dict:
        return _decode(token, self._get_client(), self.audience(), self.issuer())

    def verify(self, token: str) -> EveClaims:
        """Verified claims as EveClaims, or jwt.PyJWTError."""
        return claims_to_eve(self.verify_claims(token))


def ent_from_claims(claims: dict) -> Optional[dict]:
    """This app's entitlement from the token (`ent` keyed by the audience app), or None
    when Eve did not send one or sent a shape this SDK does not know (entv != 1)."""
    if claims.get('entv') != ENT_VERSION:
        return None
    aud = claims.get('aud')
    app = aud[0] if isinstance(aud, list) and len(aud) == 1 else aud
    ent = (claims.get('ent') or {}).get(app) if isinstance(app, str) else None
    return ent if isinstance(ent, dict) else None


def person_from_claims(claims: dict, lapsed_since: Optional[datetime] = None) -> Person:
    org = claims.get('org') or {}
    plan = claims.get('plan') or {}
    return Person(user_id=int(claims['sub']), email=claims.get('email') or '',
                  platform_role=claims.get('plat'), org_id=org.get('id'), org_type=org.get('type'),
                  org_role=org.get('role'), plan_key=plan.get('key'), plan_status=plan.get('status'),
                  plan_lapsed_since=lapsed_since, ent=ent_from_claims(claims))


def lapsed_since_from_document(doc: dict) -> Optional[datetime]:
    """When the org's plan lapsed, from Eve's access document (plan.ends_at)."""
    raw = ((doc or {}).get('plan') or {}).get('ends_at')
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace('Z', '+00:00')).astimezone(timezone.utc)
    except ValueError:
        return None
