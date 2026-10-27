"""The conformance personas: run an AppModel through the twelve cases every app must get right.

Each persona states who is asking and what is true about them; `run` calls `decide` for three
probes (a read, a write, and a feature the plan does not include) and returns the failures.
An app runs this in its own CI with its own AppModel and feature keys:

    from yisuite_access import conformance
    assert conformance.run(MyModel(), read_key='tickets.list', write_key='tickets.create',
                           out_of_plan_key='ai.assistant', plan_key='standard', role='Org Owner') == []
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from . import reasons
from .decision import Person, WorkspaceAccess, decide

NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)


def personas(plan_key: str):
    """(name, person, workspace, expectations) where expectations map probe -> allowed / refusal code."""
    live = dict(plan_key=plan_key, plan_status='active')
    owner = dict(user_id=1, org_id=5, org_type='client', org_role='owner', **live)
    ws = WorkspaceAccess('w', 'owner', 'ready')
    return [
        ('owner, plan live', Person(**owner), ws, {'read': True, 'write': True, 'out': reasons.PLAN_FEATURE}),
        ('owner, trialing', Person(**{**owner, 'plan_status': 'trialing'}), ws, {'read': True, 'write': True, 'out': reasons.PLAN_FEATURE}),
        ('owner, past due', Person(**{**owner, 'plan_status': 'past_due'}), ws, {'read': True, 'write': True, 'out': reasons.PLAN_FEATURE}),
        ('owner, lapsed 10 days', Person(**{**owner, 'plan_status': 'expired', 'plan_lapsed_since': NOW - timedelta(days=10)}), ws,
         {'read': True, 'write': reasons.ORG_READ_ONLY, 'out': reasons.PLAN_FEATURE}),
        ('owner, lapsed 40 days', Person(**{**owner, 'plan_status': 'expired', 'plan_lapsed_since': NOW - timedelta(days=40)}), ws,
         {'read': reasons.ORG_LOCKED, 'write': reasons.ORG_LOCKED, 'out': reasons.ORG_LOCKED}),
        ('viewer', Person(**owner), WorkspaceAccess('w', 'viewer', 'ready'),
         {'read': True, 'write': reasons.WORKSPACE_READ_ONLY, 'out': reasons.PLAN_FEATURE}),
        ('suspended workspace', Person(**owner), WorkspaceAccess('w', 'owner', 'suspended'),
         {'read': True, 'write': reasons.WORKSPACE_READ_ONLY, 'out': reasons.PLAN_FEATURE}),
        ('archived workspace', Person(**owner), WorkspaceAccess('w', 'owner', 'archived'),
         {'read': reasons.WORKSPACE_UNAVAILABLE, 'write': reasons.WORKSPACE_UNAVAILABLE, 'out': reasons.PLAN_FEATURE}),
        ('no access to the workspace', Person(**owner), None,
         {'read': reasons.NO_WORKSPACE_ACCESS, 'write': reasons.NO_WORKSPACE_ACCESS, 'out': reasons.PLAN_FEATURE}),
        ('anonymous', None, None, {'read': reasons.NO_CALLER, 'write': reasons.NO_CALLER, 'out': reasons.NO_CALLER}),
        ('unknown plan key', Person(**{**owner, 'plan_key': 'platinum'}), ws,
         {'read': 'UNKNOWN_PLAN_PLATINUM', 'write': 'UNKNOWN_PLAN_PLATINUM', 'out': 'UNKNOWN_PLAN_PLATINUM'}),
        ('platform admin', Person(user_id=9, platform_role='platform-admin'), ws,
         {'read': True, 'write': True, 'out': True}),
    ]


def run(model, read_key: str, write_key: str, out_of_plan_key: str, plan_key: str, role: Optional[str] = None,
        read_path='/x', write_path='/x') -> list:
    """Return a list of failure strings (empty = conforms). The model's default_role must give
    `role` to an org owner for the read/write keys to be reachable."""
    failures = []
    probes = {'read': (read_key, 'GET', read_path), 'write': (write_key, 'POST', write_path),
              'out': (out_of_plan_key, 'GET', read_path)}
    for name, person, ws, expected in personas(plan_key):
        for probe, (key, method, path) in probes.items():
            d = decide(person, ws, [key], method, path, model, now=NOW)
            want = expected[probe]
            got = True if d.allowed else d.code
            # the 'out of plan' probe is judged only on plan and refusals before the plan
            if probe == 'out' and want == reasons.PLAN_FEATURE and not d.allowed and d.code == reasons.PLAN_FEATURE:
                continue
            if got != want:
                failures.append(f'{name} / {probe}: expected {want}, got {got}')
    return failures
