"""The folded token verifier, the Eve client calls, and the token conformance suite run on ourselves."""
import pytest

from yisuite_access import token_conformance
from yisuite_access.client import EveClient, EveUnavailable
from yisuite_access.tokens import EnvVerifier, TokenVerifier, bearer, looks_like_rs256, token_mode

KEYS = token_conformance.TestKeys()


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ('EVE_TOKEN_MODE', 'EVE_API_URL', 'EVE_JWKS_URL', 'EVE_TOKEN_ISSUER', 'YISUITE_APP_SLUG'):
        monkeypatch.delenv(k, raising=False)


def env_verify(token, jwk_client):
    v = EnvVerifier('yimport')
    v._get_client = lambda: jwk_client
    return v.verify(token)


def explicit_verify(token, jwk_client):
    return TokenVerifier('yimport', 'unused', jwk_client=jwk_client).verify(token)


# the suite apps run, run here on both verifiers
globals().update(token_conformance.make_tests('yimport', env_verify))


def test_explicit_verifier_conforms():
    assert token_conformance.run('yimport', explicit_verify, KEYS) == []


def test_conformance_accepts_an_app_user_dict():
    def user_dict(token, jwk_client):
        c = env_verify(token, jwk_client)
        return {'id': c.user_id, 'email': c.email, 'ent': c.ent}
    assert token_conformance.run('yimport', user_dict, KEYS) == []


def test_conformance_catches_a_user_dict_with_wrong_ent():
    def wrong(token, jwk_client):
        env_verify(token, jwk_client)
        return {'id': '42', 'ent': {'features': ['other']}}
    assert token_conformance.run('yimport', wrong, KEYS)


def test_conformance_catches_a_lax_verifier():
    import jwt

    def lax(token, _):
        return jwt.decode(token, options={'verify_signature': False})
    assert token_conformance.run('yimport', lax, KEYS)


def test_claims_parsed():
    c = env_verify(KEYS.mint('yimport'), KEYS.jwk_client())
    assert (c.user_id, c.email, c.name, c.org_id, c.org_role, c.tid, c.ent) == \
        ('42', 'a@b.c', 'A B', 5, 'owner', 't-7', {'features': ['x']})


@pytest.mark.parametrize('raw,mode,enabled', [(None, 'off', False), ('', 'off', False), ('off', 'off', False),
                                              ('both', 'both', True), (' V2 ', 'v2', True), ('yes', 'off', False)])
def test_mode(monkeypatch, raw, mode, enabled):
    if raw is not None:
        monkeypatch.setenv('EVE_TOKEN_MODE', raw)
    assert token_mode() == mode and EnvVerifier('x').enabled() is enabled


def test_env_settings(monkeypatch):
    v = EnvVerifier('yimport')
    assert (v.audience(), v.issuer(), v.jwks_url()) == ('yimport', 'https://api.3v3.ai',
                                                        'https://api.3v3.ai/.well-known/jwks.json')
    monkeypatch.setenv('EVE_API_URL', 'https://eve.test/')
    monkeypatch.setenv('YISUITE_APP_SLUG', 'other')
    assert (v.audience(), v.jwks_url()) == ('other', 'https://eve.test/.well-known/jwks.json')
    monkeypatch.setenv('EVE_JWKS_URL', 'https://k.test/jwks')
    assert v.jwks_url() == 'https://k.test/jwks'


def test_jwks_client_names_itself(monkeypatch):
    import jwt
    seen = {}

    class Spy:
        def __init__(self, url, **kw):
            seen.update(url=url, **kw)
    monkeypatch.setattr(jwt, 'PyJWKClient', Spy)
    EnvVerifier('yimport')._get_client()
    assert seen['url'] == 'https://api.3v3.ai/.well-known/jwks.json'
    assert 'urllib' not in seen['headers']['User-Agent'].lower() and 'yisuite-access/' in seen['headers']['User-Agent']
    assert seen['timeout'] == 8 and seen['lifespan'] == 600


def test_bearer_and_alg_peek():
    assert bearer('Bearer abc') == 'abc' and bearer('bearer  abc ') == 'abc'
    assert bearer('Basic abc') is None and bearer('Bearer ') is None and bearer(None) is None
    assert looks_like_rs256(KEYS.mint('a')) and not looks_like_rs256(KEYS.mint('a', alg='HS256'))
    assert not looks_like_rs256('garbage')


class Resp:
    def __init__(self, status, body=None):
        self.status_code, self._b = status, body or {}

    def json(self):
        return self._b


class Http:
    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a


def client(http, secret='s'):
    return EveClient('https://eve.test/', secret, http=http, app_slug='yimport', sleep=lambda s: None)


def test_reporting_is_noop_without_secret():
    http = Http()
    c = client(http, secret='')
    assert c.publish_catalog({}) is None and c.notify('t', 'x', {'user_ids': [1]}) is None
    assert c.report_usage('co', [{'limit': 'docs', 'quantity': 1}]) is None and c.health_event('boot') is None
    assert http.calls == []
    with pytest.raises(EveUnavailable):
        c.read_usage('co')


def test_calls_shape_and_headers():
    http = Http(*[Resp(200, {'success': True})] * 5)
    c = client(http)
    c.publish_catalog({'features': []})
    c.notify('doc.ready', 'Ready', {'user_ids': [1]}, dedupe_key='doc-1')
    c.report_usage('co', [{'limit': 'docs', 'quantity': 1, 'event_id': 'doc-1'}, {'limit': 'docs', 'quantity': 2}])
    c.read_usage('co', at='2026-11-01')
    c.health_event('boot', detail={'v': 1})
    (m0, u0, k0), (m1, u1, k1), (m2, u2, k2), (m3, u3, k3), (m4, u4, k4) = http.calls
    assert (m0, u0) == ('PUT', 'https://eve.test/api/access/catalog')
    assert (m1, u1, k1['json']['dedupe_key']) == ('POST', 'https://eve.test/api/notify/events', 'doc-1')
    assert (m2, u2) == ('POST', 'https://eve.test/api/access/usage') and k2['json']['tenant'] == 'co'
    ids = [e['event_id'] for e in k2['json']['events']]
    assert ids[0] == 'doc-1' and ids[1].startswith('u-')
    assert (m3, u3, k3['params']) == ('GET', 'https://eve.test/api/access/usage/co', {'at': '2026-11-01'})
    assert u4 == 'https://eve.test/api/access/suite-events' and k4['json']['events'][0]['kind'] == 'boot'
    for _, _, kw in http.calls:
        assert kw['headers']['Authorization'] == 'Bearer s' and kw['timeout'] == 8.0
        assert kw['headers']['User-Agent'].startswith('yisuite-access/')


def test_retries_transient_then_succeeds_with_same_key():
    import requests
    http = Http(requests.ConnectionError('x'), Resp(503), Resp(201, {'success': True}))
    assert client(http).notify('t', 'x', {'user_ids': [1]})['success']
    keys = {kw['json']['dedupe_key'] for _, _, kw in http.calls}
    assert len(http.calls) == 3 and len(keys) == 1


def test_gives_up_after_retries_and_does_not_retry_4xx():
    http = Http(Resp(503), Resp(503), Resp(503))
    with pytest.raises(EveUnavailable):
        client(http).health_event('x')
    http = Http(Resp(403))
    with pytest.raises(EveUnavailable):
        client(http).publish_catalog({})
    assert len(http.calls) == 1


def test_redeem_is_never_retried():
    import requests
    http = Http(requests.ConnectionError('x'))
    with pytest.raises(EveUnavailable):
        client(http).redeem('code')
    assert len(http.calls) == 1
