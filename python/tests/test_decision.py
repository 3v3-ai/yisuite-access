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


# ── Eve's resolved entitlement (`ent`) ──────────────────────────────────────

from yisuite_access import ent_from_claims, org_allows, org_limit, quota_refusal
from yisuite_access.tokens import person_from_claims

ENT = {'b': ['core'], 'add': ['ai.assistant'], 'rm': ['tickets.view'], 'lim': {'tickets_per_month': 100, 'seats': None},
       'cat': 'h', 'st': 'live'}


def test_org_allows_bundles_added_removed_and_platform_keys():
    assert org_allows(ENT, 'tickets.list', M) is True
    assert org_allows(ENT, 'tickets.view', M) is False           # removed for this company
    assert org_allows(ENT, 'ai.assistant', M) is True            # added though 'ai' is not a bundle here
    assert org_allows(ENT, 'banking.import', M) is False
    assert org_allows(ENT, 'admin.tenants', M) is True           # platform: the role decides


def test_limits_and_quota_refusal():
    assert org_limit(ENT, 'tickets_per_month') == 100
    assert org_limit(ENT, 'seats') is None and org_limit(ENT, 'missing') is None and org_limit(None, 'x') is None
    assert quota_refusal(ENT, 'tickets_per_month', used=99) is None
    r = quota_refusal(ENT, 'tickets_per_month', used=100, subscribe_url='https://3v3.ai/billing')
    assert r.code == reasons.QUOTA_EXCEEDED and r.status == 402
    assert r.body()['allowed'] == 100 and r.body()['used'] == 100 and r.body()['subscribe_url']
    assert quota_refusal(ENT, 'seats', used=10**6) is None


def test_ent_answers_step_3_instead_of_the_plan_key():
    # An unknown plan key would be refused; with ent present it is never read.
    p = Person(user_id=1, org_id=5, org_role='owner', plan_key='platinum', plan_status='active', ent={'b': ['core'], 'st': 'live'})
    assert decide(p, WorkspaceAccess('w', 'owner'), ['tickets.list'], 'GET', '/t', M, now=NOW).allowed
    d = decide(p, WorkspaceAccess('w', 'owner'), ['banking.import'], 'GET', '/b', M, now=NOW)
    assert d.code == reasons.PLAN_FEATURE


def test_ent_from_claims_reads_the_audience_app_and_the_version():
    claims = {'sub': '1', 'aud': 'yiflow', 'entv': 1, 'ent': {'yiflow': ENT, 'other': {'b': []}}}
    assert ent_from_claims(claims) == ENT
    assert ent_from_claims({**claims, 'aud': ['yiflow']}) == ENT
    assert ent_from_claims({**claims, 'entv': 2}) is None         # a shape this SDK does not know
    assert ent_from_claims({**claims, 'aud': 'nope'}) is None
    assert person_from_claims(claims).ent == ENT
