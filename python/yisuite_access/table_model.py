"""An AppModel described by plain data, for apps whose rules are prefixes and lists.

The same table works in the Node SDK, which is how the two are tested against one
contract (contracts/decision_cases.json).
"""

from __future__ import annotations

from typing import Iterable, Optional

from .decision import PLATFORM


class TableModel:
    def __init__(self, plans: dict, roles: dict, owners: list, default_roles: dict,
                 read_markers: Iterable[str] = ('report', 'export'), export_markers: Iterable[str] = ('export',)):
        self.plans = {k: set(v) for k, v in plans.items()}
        self.roles = roles
        self.owners = [(p, b) for p, b in owners]
        self.default_roles = default_roles
        self.read_markers = tuple(read_markers)
        self.export_markers = tuple(export_markers)

    def to_dict(self) -> dict:
        return {'plans': {k: sorted(v) for k, v in self.plans.items()}, 'roles': self.roles,
                'owners': [[p, b] for p, b in self.owners], 'default_roles': self.default_roles,
                'read_markers': list(self.read_markers), 'export_markers': list(self.export_markers)}

    @classmethod
    def from_dict(cls, d: dict) -> 'TableModel':
        return cls(d['plans'], d['roles'], d['owners'], d['default_roles'], d['read_markers'], d['export_markers'])

    def bundle_for_key(self, key: str) -> Optional[str]:
        best, best_len = None, -1
        for prefix, bundle in self.owners:
            if key == prefix or (key.startswith(prefix) and key[len(prefix):len(prefix) + 1] in ('.', '-')):
                if len(prefix) > best_len:
                    best, best_len = bundle, len(prefix)
        return best

    def plan_bundles(self, plan_key: str):
        return self.plans.get(plan_key)

    def role_keys(self, role: str):
        return self.roles.get(role, [])

    def default_role(self, org_role: Optional[str]):
        return self.default_roles.get(org_role or '')

    def is_write(self, method: str, path: str) -> bool:
        return method not in ('GET', 'HEAD', 'OPTIONS') and not any(m in path for m in self.read_markers)

    def is_export(self, path: str) -> bool:
        return any(m in path for m in self.export_markers)


EXAMPLE = TableModel(
    plans={'starter': ['core'], 'standard': ['core', 'banking'], 'premium': ['core', 'banking', 'ai']},
    roles={'Owner': ['tickets', 'banking', 'ai', 'admin'], 'Member': ['tickets.list', 'tickets.view'],
           'Accountant': ['tickets', 'banking']},
    owners=[['admin', PLATFORM], ['tickets', 'core'], ['banking', 'banking'], ['ai', 'ai']],
    default_roles={'owner': 'Owner', 'admin': 'Owner', 'member': 'Member'})
