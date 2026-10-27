import hashlib
import hmac
import json

import pytest

flask = pytest.importorskip('flask')

from yisuite_access.client import EveUnavailable
from yisuite_access.flask_adapter import YisuiteAccess
from tests.example_model import ExampleModel


class Verifier:
    """Stands in for Eve's tokens: the token text is the user id; 'bad' is refused."""
    def verify(self, token):
        if token == 'bad':
            raise ValueError('bad token')
        uid = int(token)
        return {'sub': str(uid), 'email': f'u{uid}@x', 'org': {'id': 5, 'type': 'client', 'role': 'owner' if uid == 1 else 'member'},
                'plan': {'key': 'standard', 'status': 'active'}, 'plat': None}


class Client:
    def __init__(self):
        self.docs = {1: {'workspaces': [{'key': 'acme', 'level': 'owner', 'status': 'ready'}]},
                     2: {'workspaces': [{'key': 'acme', 'level': 'viewer', 'status': 'ready'}]}}
        self.calls = 0
        self.down = False

    def access_for(self, uid, org=None):
        self.calls += 1
        if self.down:
            raise EveUnavailable('down')
        return self.docs.get(uid)

    def redeem(self, code):
        return {'token': '1'} if code == 'good' else None


@pytest.fixture
def env():
    app = flask.Flask('t'); app.secret_key = 's'
    client = Client()
    access = YisuiteAccess('yiflow', 'https://eve.test', ExampleModel(), webhook_secret='wh', verifier=Verifier(), client=client)
    access.init_app(app)

    @app.get('/health')
    @access.public(reason='probe')
    def health(): return 'ok'

    @app.get('/tickets')
    @access.require(feature='tickets.list', workspace=lambda: flask.request.args.get('company'))
    def tickets(): return 'tickets'

    @app.post('/tickets')
    @access.require(feature='tickets.create', workspace=lambda: flask.request.args.get('company'))
    def create(): return 'created'

    @app.get('/undecorated')
    def undecorated(): return 'u'

    return app.test_client(), client, access


def auth(uid): return {'Authorization': f'Bearer {uid}'}


def test_public_routes_need_nothing_and_undecorated_ones_need_a_person(env):
    c, _, _ = env
    assert c.get('/health').status_code == 200
    assert c.get('/undecorated').status_code == 401
    assert c.get('/undecorated', headers=auth(1)).status_code == 200
    assert c.get('/undecorated', headers=auth('bad')).status_code == 401


def test_a_decorated_route_decides_with_eves_workspace_and_level(env):
    c, _, _ = env
    assert c.get('/tickets?company=acme', headers=auth(1)).status_code == 200
    assert c.get('/tickets?company=other', headers=auth(1)).get_json()['error_code'] == 'NO_WORKSPACE_ACCESS'
    assert c.get('/tickets', headers=auth(1)).get_json()['error_code'] == 'NO_WORKSPACE_ACCESS'
    assert c.get('/tickets?company=acme').get_json()['error_code'] == 'NO_CALLER'


def test_a_viewer_reads_but_does_not_write(env):
    c, _, _ = env
    assert c.get('/tickets?company=acme', headers=auth(2)).status_code == 200
    r = c.post('/tickets?company=acme', headers=auth(2))
    assert r.status_code == 403 and r.get_json()['error_code'] == 'WORKSPACE_READ_ONLY'
    assert c.post('/tickets?company=acme', headers=auth(1)).status_code == 200


def test_the_document_is_cached_and_events_drop_it(env):
    c, client, _ = env
    c.get('/tickets?company=acme', headers=auth(1)); c.get('/tickets?company=acme', headers=auth(1))
    assert client.calls == 1
    body = json.dumps({'id': 7, 'topic': 'grant.changed'}).encode()
    sig = 'sha256=' + hmac.new(b'wh', body, hashlib.sha256).hexdigest()
    assert c.post('/_yisuite/events', data=body, content_type='application/json', headers={'X-Yisuite-Signature': sig}).status_code == 200
    assert c.post('/_yisuite/events', data=body, content_type='application/json', headers={'X-Yisuite-Signature': sig}).get_json()['duplicate']
    c.get('/tickets?company=acme', headers=auth(1))
    assert client.calls == 2
    assert c.post('/_yisuite/events', data=body, content_type='application/json', headers={'X-Yisuite-Signature': 'sha256=00'}).status_code == 401


def test_eve_down_denies_unless_there_is_a_recent_answer(env):
    c, client, access = env
    client.down = True
    assert c.get('/tickets?company=acme', headers=auth(1)).status_code == 503        # never an allow
    client.down = False
    c.get('/tickets?company=acme', headers=auth(1))
    client.down = True
    access.doc_ttl = 0                                                               # expired, still recent
    assert c.get('/tickets?company=acme', headers=auth(1)).status_code == 200        # stale beats locked out


def test_handoff_redeems_a_code_into_a_session(env):
    c, _, _ = env
    assert c.post('/_yisuite/handoff', json={}).status_code == 400
    assert c.post('/_yisuite/handoff', json={'code': 'spent'}).status_code == 401
    assert c.post('/_yisuite/handoff', json={'code': 'good'}).status_code == 200
    # the session now carries the token: no header needed
    with c.session_transaction() as s:
        assert s['ys_token'] == '1'


def test_a_browser_is_sent_to_sign_in_not_shown_json(env):
    c, _, _ = env
    r = c.get('/tickets?company=acme', headers={'Accept': 'text/html'})
    assert r.status_code == 302 and 'login' in r.headers['Location']
