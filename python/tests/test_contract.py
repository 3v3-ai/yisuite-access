"""The Python SDK replays the shared contract (the Node SDK replays the same file)."""

import json
import os
from datetime import datetime

import pytest

from yisuite_access.decision import Person, WorkspaceAccess, decide
from yisuite_access.table_model import TableModel

DOC = json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'contracts', 'decision_cases.json')))
MODEL = TableModel.from_dict(DOC['model'])


def when(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00')) if s else None


@pytest.mark.parametrize('case', DOC['cases'], ids=[c['name'] for c in DOC['cases']])
def test_case(case):
    p = case['person']
    person = Person(**{**p, 'plan_lapsed_since': when(p.get('plan_lapsed_since'))}) if p else None
    ws = WorkspaceAccess(**case['workspace']) if case['workspace'] else None
    d = decide(person, ws, case['keys'], case['method'], case['path'], MODEL, now=when(case['now']))
    e = case['expect']
    assert (d.allowed, d.code, d.refusal.status if d.refusal else None, d.role, d.level) == \
           (e['allowed'], e['code'], e['status'], e['role'], e['level'])
