"""Token conformance: the cases every app's Eve-token path must get right, as pytest tests.

An app adds one file to its test suite and runs it in CI:

    # tests/test_yisuite_token_conformance.py
    from yisuite_access.token_conformance import make_tests

    def verify(token, jwk_client):
        # call YOUR app's verification path with Eve's JWKS replaced by jwk_client;
        # return the verified claims (dict or object with .ent / .user_id) or raise
        ...

    globals().update(make_tests(audience='yimport', verify=verify))

Cases: good token accepted (ent parsed), wrong audience, wrong issuer, expired, unknown kid,
wrong key, HS256 refused, token without ent (accepted, ent None), entv it does not know (ent None).
"""

from __future__ import annotations

import time
from typing import Callable, Optional

ISSUER = 'https://api.3v3.ai'
KID = 'eve-test-1'


class TestKeys:
    """An RS256 key pair and a JWKS stand-in that knows only KID."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwk_client(self):
        import jwt
        pub = self.key.public_key()

        class Jwks:
            def get_signing_key_from_jwt(self, token):
                kid = jwt.get_unverified_header(token).get('kid')
                if kid != KID:
                    raise jwt.PyJWKClientError(f'Unable to find a signing key that matches: "{kid}"')

                class K:
                    key = pub
                return K()
        return Jwks()

    def mint(self, audience: str, key=None, kid: str = KID, alg: str = 'RS256', drop=(), **over) -> str:
        import jwt
        now = int(time.time())
        claims = {'iss': ISSUER, 'aud': audience, 'sub': '42', 'email': 'a@b.c', 'name': 'A B',
                  'iat': now, 'exp': now + 900, 'tid': 't-7', 'org': {'id': 5, 'role': 'owner'},
                  'entv': 1, 'ent': {audience: {'features': ['x']}}}
        claims.update(over)
        for k in drop:
            claims.pop(k, None)
        if alg == 'HS256':
            return jwt.encode(claims, 'shared-secret-that-must-not-work-0123456789', algorithm='HS256',
                              headers={'kid': kid})
        return jwt.encode(claims, key or self.key, algorithm='RS256', headers={'kid': kid})


def _ent(result):
    """ent from what the app's verify returned: a claims dict, or an object with .ent."""
    if isinstance(result, dict):
        from .tokens import ent_from_claims
        return ent_from_claims(result)
    return getattr(result, 'ent', None)


def cases(audience: str):
    """(name, minter(keys) -> token, expected) where expected is 'reject' or the ent dict/None."""
    t = int(time.time())
    return [
        ('good token', lambda k: k.mint(audience), {'features': ['x']}),
        ('wrong audience', lambda k: k.mint(audience, aud='some-other-app'), 'reject'),
        ('wrong issuer', lambda k: k.mint(audience, iss='https://evil.example'), 'reject'),
        ('expired', lambda k: k.mint(audience, iat=t - 2000, exp=t - 60), 'reject'),
        ('unknown kid', lambda k: k.mint(audience, kid='rotated-away'), 'reject'),
        ('signed by another key', lambda k: k.mint(audience, key=k.other), 'reject'),
        ('HS256 instead of RS256', lambda k: k.mint(audience, alg='HS256'), 'reject'),
        ('no exp claim', lambda k: k.mint(audience, drop=('exp',)), 'reject'),
        ('no ent', lambda k: k.mint(audience, drop=('ent', 'entv')), None),
        ('unknown entv', lambda k: k.mint(audience, entv=2), None),
    ]


def run(audience: str, verify: Callable, keys: Optional[TestKeys] = None) -> list:
    """Failure strings; empty means the app's path conforms."""
    return _run_cases(audience, verify, keys or TestKeys(), cases(audience))


def make_tests(audience: str, verify: Callable) -> dict:
    """pytest test functions, one per case, for the caller's module globals."""
    out = {}
    for name, _, _ in cases(audience):
        def test(name=name):
            keys = TestKeys()
            one = [c for c in cases(audience) if c[0] == name]
            assert _run_cases(audience, verify, keys, one) == []
        out['test_eve_token_' + name.replace(' ', '_').lower()] = test
    return out


def _run_cases(audience, verify, keys, selected):
    import jwt
    failures = []
    for name, minter, want in selected:
        try:
            got = verify(minter(keys), keys.jwk_client())
        except (jwt.PyJWTError, ValueError) as e:
            if want != 'reject':
                failures.append(f'{name}: expected accepted, got rejected ({e})')
            continue
        if want == 'reject':
            failures.append(f'{name}: expected rejected, got accepted')
        elif got is None:
            failures.append(f'{name}: verify returned nothing for a valid token')
        elif _ent(got) != want:
            failures.append(f'{name}: expected ent {want!r}, got {_ent(got)!r}')
    return failures
