import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from yisuite_access import conformance, covers, decide, reasons
from yisuite_access.decision import Person, WorkspaceAccess
from tests.example_model import ExampleModel

M = ExampleModel()
VECTORS = json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'contracts', 'key_cover_cases.json')))['cases']
NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)


@pytest.mark.parametrize('c', VECTORS, ids=[c['why'] for c in VECTORS])
def test_the_shared_key_vectors(c):
    assert covers(c['held'], c['want'], c['parent']) is c['expect']


def test_the_twelve_personas_conform():
    assert conformance.run(M, read_key='tickets.list', write_key='tickets.create',
                           out_of_plan_key='ai.assistant', plan_key='standard') == []


def test_the_suite_catches_a_model_that_ignores_the_plan():
    class Lax(ExampleModel):
        def plan_bundles(self, plan_key):
            return {'core', 'ai'} if plan_key in ('standard', 'premium') else None
    failures = conformance.run(Lax(), 'tickets.list', 'tickets.create', 'ai.assistant', 'standard')
    assert any('PLAN_FEATURE' in f for f in failures)


def test_the_suite_catches_a_model_that_lets_viewers_write():
    class Loose(ExampleModel):
        def is_write(self, method, path):
            return False
    assert conformance.run(Loose(), 'tickets.list', 'tickets.create', 'ai.assistant', 'standard')


def p(**kw):
    base = dict(user_id=1, org_id=5, org_type='client', org_role='owner', plan_key='standard', plan_status='active')
    base.update(kw)
    return Person(**base)


W = WorkspaceAccess('w', 'owner', 'ready')


def go(person, ws=W, keys=('tickets.list',), method='GET', path='/x', **kw):
    return decide(person, ws, list(keys), method, path, M, now=NOW, **kw)


def test_first_refusal_wins_in_order():
    assert go(None).code == reasons.NO_CALLER                                  # 1 caller
    assert go(p(org_id=None, org_role=None), ws=None).code == reasons.NO_ORG   # 2 org
    assert go(p(plan_status='expired', plan_lapsed_since=NOW - timedelta(days=99)), ws=None).code == reasons.ORG_LOCKED   # 3 plan before 4
    assert go(p(), ws=None).code == reasons.NO_WORKSPACE_ACCESS                # 4 workspace
    assert go(p(), WorkspaceAccess('w', 'owner', 'archived')).code == reasons.WORKSPACE_UNAVAILABLE   # 5 state
    assert go(p(org_role='member'), keys=('ai.assistant',)).code in (reasons.PLAN_FEATURE, reasons.FEATURE_ACCESS_DENIED)


def test_a_workspace_role_from_eve_beats_the_org_role():
    member = p(org_role='member')
    assert not go(member, keys=('tickets.create',)).allowed                    # Member only lists
    assert go(member, WorkspaceAccess('w', 'editor', 'ready', app_role='Owner'), keys=('tickets.create',), method='POST').allowed


def test_a_refusal_carries_what_to_do_next():
    d = go(p(plan_key='standard'), keys=('ai.assistant',), subscribe_url='https://www.3v3.ai/billing')
    assert d.refusal.body()['next_action'] and d.refusal.body()['subscribe_url'].endswith('/billing')


def test_unknown_things_are_refused_and_named():
    assert go(p(plan_key='platinum')).code == 'UNKNOWN_PLAN_PLATINUM'
    assert go(p(plan_status='frozen')).code.startswith('UNKNOWN_PLAN_STATUS')
    assert go(p(), keys=('mystery.key',), ).code == reasons.PLAN_FEATURE         # an unowned key is closed


def test_platform_admin_is_not_plan_limited_but_support_needs_a_workspace():
    admin = Person(user_id=9, platform_role='platform-admin')
    assert go(admin, keys=('ai.assistant',)).allowed
    assert go(Person(user_id=8, platform_role='support'), ws=None).code == reasons.NO_WORKSPACE_ACCESS
