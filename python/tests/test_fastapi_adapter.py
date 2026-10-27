import hashlib
import hmac
import json

import pytest

fastapi = pytest.importorskip('fastapi')
pytest.importorskip('httpx')
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from yisuite_access.client import EveUnavailable
from yisuite_access.fastapi_adapter import YisuiteAccessFastAPI
from tests.example_model import ExampleModel
from tests.test_flask_adapter import Client, Verifier


@pytest.fixture
def env():
    app = FastAPI()
    client = Client()
    access = YisuiteAccessFastAPI('yimport', 'https://eve.test', ExampleModel(), webhook_secret='wh',
                                  verifier=Verifier(), client=client, public=['/health'], secure_cookie=False)
    access.install(app)

    @app.get('/health')
    def health(): return {'ok': True}

    @app.get('/open')
    def open_(): return {'ok': True}

    @app.get('/tickets')
    def tickets(d=Depends(access.require('tickets.list', workspace=lambda r: r.query_params.get('company')))):
        return {'role': d.role}

    @app.post('/tickets')
    def create(d=Depends(access.require('tickets.create', workspace=lambda r: r.query_params.get('company')))):
        return {'created': True}

    return TestClient(app), client, access


def auth(uid): return {'Authorization': f'Bearer {uid}'}


def test_the_gate(env):
    c, _, _ = env
    assert c.get('/health').status_code == 200
    assert c.get('/open').status_code == 401
    assert c.get('/open', headers=auth(1)).status_code == 200
    assert c.get('/open', headers=auth('bad')).status_code == 401
    r = c.get('/open', headers={'Accept': 'text/html'}, follow_redirects=False)
    assert r.status_code == 302 and 'login' in r.headers['location']


def test_the_decision_uses_eves_workspace_and_level(env):
    c, _, _ = env
    assert c.get('/tickets?company=acme', headers=auth(1)).json() == {'role': 'Owner'}
    assert c.get('/tickets?company=other', headers=auth(1)).json()['error_code'] == 'NO_WORKSPACE_ACCESS'
    assert c.get('/tickets', headers=auth(1)).json()['error_code'] == 'NO_WORKSPACE_ACCESS'
    assert c.get('/tickets?company=acme', headers=auth(2)).status_code == 200
    r = c.post('/tickets?company=acme', headers=auth(2))
    assert r.status_code == 403 and r.json()['error_code'] == 'WORKSPACE_READ_ONLY'
    assert c.post('/tickets?company=acme', headers=auth(1)).status_code == 200


def test_events_and_handoff(env):
    c, client, access = env
    body = json.dumps({'id': 3, 'topic': 'grant.changed'}).encode()
    sig = 'sha256=' + hmac.new(b'wh', body, hashlib.sha256).hexdigest()
    assert c.post('/_yisuite/events', content=body, headers={'X-Yisuite-Signature': sig}).status_code == 200
    assert c.post('/_yisuite/events', content=body, headers={'X-Yisuite-Signature': sig}).json()['duplicate']
    assert c.post('/_yisuite/events', content=body, headers={'X-Yisuite-Signature': 'sha256=00'}).status_code == 401
    assert c.post('/_yisuite/handoff', json={}).status_code == 400
    assert c.post('/_yisuite/handoff', json={'code': 'spent'}).status_code == 401
    ok = c.post('/_yisuite/handoff', json={'code': 'good'})
    assert ok.status_code == 200 and 'ys_token=1' in ok.headers['set-cookie']
    assert c.get('/open').status_code == 200                # the cookie now carries the token


def test_eve_down_never_allows(env):
    c, client, _ = env
    client.down = True
    assert c.get('/tickets?company=acme', headers=auth(1)).status_code == 503
