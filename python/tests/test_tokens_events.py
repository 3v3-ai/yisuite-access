import hashlib
import hmac
import time

import pytest

jwt = pytest.importorskip('jwt')
rsa = pytest.importorskip('cryptography.hazmat.primitives.asymmetric.rsa')

from yisuite_access import events
from yisuite_access.tokens import TokenVerifier, lapsed_since_from_document, person_from_claims


@pytest.fixture(scope='module')
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeJwks:
    def __init__(self, key): self.key = key
    def get_signing_key_from_jwt(self, token):
        class K: pass
        k = K(); k.key = self.key.public_key(); return k


def token(key, **over):
    now = int(time.time())
    claims = {'sub': '66', 'email': 'm@x.com', 'iss': 'https://api.3v3.ai', 'aud': 'yiflow', 'iat': now, 'exp': now + 900,
              'org': {'id': 5, 'type': 'client', 'role': 'owner'}, 'plan': {'key': 'standard', 'status': 'active'}, 'plat': None}
    claims.update(over)
    return jwt.encode(claims, key, algorithm='RS256')


def test_verifies_audience_issuer_and_expiry(key):
    v = TokenVerifier('yiflow', 'unused', jwk_client=FakeJwks(key))
    assert v.verify(token(key))['sub'] == '66'
    for bad in ({'aud': 'yincome'}, {'iss': 'https://evil'}, {'exp': int(time.time()) - 5}):
        with pytest.raises(jwt.PyJWTError):
            v.verify(token(key, **bad))
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(jwt.PyJWTError):
        v.verify(token(other))


def test_claims_become_a_person(key):
    p = person_from_claims(TokenVerifier('yiflow', 'u', jwk_client=FakeJwks(key)).verify(token(key)))
    assert (p.user_id, p.org_id, p.org_role, p.plan_key, p.plan_status) == (66, 5, 'owner', 'standard', 'active')


def test_lapse_date_from_the_document():
    assert lapsed_since_from_document({'plan': {'ends_at': '2026-09-01T00:00:00.000Z'}}).year == 2026
    assert lapsed_since_from_document({}) is None
    assert lapsed_since_from_document({'plan': {'ends_at': 'garbage'}}) is None


def test_event_signatures_and_dedupe():
    body = b'{"id":1}'
    sig = 'sha256=' + hmac.new(b's3', body, hashlib.sha256).hexdigest()
    assert events.signature_ok('s3', body, sig)
    assert not events.signature_ok('other', body, sig)
    assert not events.signature_ok('s3', body + b'x', sig)
    assert not events.signature_ok('', body, sig)
    d = events.Dedupe()
    assert d.first_time(5) and not d.first_time(5)
    d.forget(5)
    assert d.first_time(5)
