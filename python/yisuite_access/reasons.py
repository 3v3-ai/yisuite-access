"""Stable refusal codes and one body shape, shared by every app and by the frontend."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

NO_CALLER = 'NO_CALLER'
NO_ORG = 'NO_ORG'
NO_APP_ACCESS = 'NO_APP_ACCESS'
ORG_READ_ONLY = 'ORG_READ_ONLY'
ORG_LOCKED = 'ORG_LOCKED'
PLAN_FEATURE = 'PLAN_FEATURE'
SEAT_LIMIT = 'SEAT_LIMIT'
QUOTA_EXCEEDED = 'QUOTA_EXCEEDED'
NO_WORKSPACE_ACCESS = 'NO_WORKSPACE_ACCESS'
WORKSPACE_READ_ONLY = 'WORKSPACE_READ_ONLY'
WORKSPACE_UNAVAILABLE = 'WORKSPACE_UNAVAILABLE'
FEATURE_ACCESS_DENIED = 'FEATURE_ACCESS_DENIED'


def unknown(thing: str) -> str:
    return 'UNKNOWN_' + ''.join(c if c.isalnum() else '_' for c in thing).upper()


@dataclass(frozen=True)
class Refusal:
    code: str
    status: int
    message: str
    next_action: str = ''
    extra: dict = field(default_factory=dict)

    def body(self) -> dict:
        out = {'success': False, 'error': self.message, 'error_code': self.code}
        if self.next_action:
            out['next_action'] = self.next_action
        out.update(self.extra)
        return out
