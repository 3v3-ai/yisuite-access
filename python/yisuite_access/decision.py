"""The access decision: six checks, first refusal wins, anything unknown is a no.

  1 caller      who is asking (a verified person)
  2 org         an organization the person acts for (platform staff need none)
  3 plan        the company's entitlement for this app (Eve's `ent` claim: bundles, single
                keys, limits, live / read-only / locked); without one, the org's plan key
                and the app's plan -> bundle table (the older path)
  4 workspace   the person's level in the workspace the request names
  5 state       the workspace's state: ready open, suspended read-only, others hidden
  6 feature     the role's feature keys, level (viewer = read-only)

The app supplies an AppModel (its feature keys, plan bundles and roles); everything else
is common. `decide` is a pure function: no I/O, no framework, trivially testable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional, Protocol

from . import reasons
from .keys import covers
from .reasons import Refusal

PLATFORM = 'platform'
READ_ONLY_DAYS = 30
LIVE = ('trialing', 'active', 'past_due')
LAPSED = ('expired', 'canceled', 'cancelled')


class AppModel(Protocol):
    """What an app declares about itself."""

    def bundle_for_key(self, feature_key: str) -> Optional[str]:
        """The plan bundle that owns a key, PLATFORM, or None (unowned: closed)."""

    def plan_bundles(self, plan_key: str) -> Optional[Iterable[str]]:
        """The bundles a plan includes, or None when the plan key is unknown."""

    def role_keys(self, role_name: str) -> Iterable[str]:
        """The feature keys a named role grants."""

    def default_role(self, org_role: Optional[str]) -> Optional[str]:
        """The role a person gets from their org role when no workspace role is set."""

    def is_write(self, method: str, path: str) -> bool:
        """True when the request changes the workspace's data."""

    def is_export(self, path: str) -> bool:
        """True for exports and billing, which a locked org may still use."""


@dataclass(frozen=True)
class Person:
    user_id: int
    email: str = ''
    platform_role: Optional[str] = None            # 'platform-admin' | 'support' | None
    org_id: Optional[int] = None
    org_type: Optional[str] = None
    org_role: Optional[str] = None
    plan_key: Optional[str] = None
    plan_status: Optional[str] = None
    plan_lapsed_since: Optional[datetime] = None
    # This app's entitlement as Eve resolved it for the company ({b, add, rm, lim, cat, st}).
    # When set, it alone answers step 3: no plan key or plan table is read.
    ent: Optional[dict] = None


@dataclass(frozen=True)
class WorkspaceAccess:
    key: str
    level: str = 'editor'                          # owner | editor | viewer
    status: str = 'ready'
    app_role: Optional[str] = None
    data_window: Optional[dict] = None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: Optional[str] = None
    refusal: Optional[Refusal] = None
    role: Optional[str] = None
    level: Optional[str] = None

    @classmethod
    def ok(cls, role=None, level=None):
        return cls(True, role=role, level=level)

    @classmethod
    def no(cls, refusal: Refusal):
        return cls(False, code=refusal.code, refusal=refusal)


def lapse_stage(since: Optional[datetime], now: datetime) -> str:
    """read_only within READ_ONLY_DAYS of the lapse, locked after. An unknown date is never locked on a guess."""
    if since is None:
        return 'read_only'
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    return 'locked' if now >= since + timedelta(days=READ_ONLY_DAYS) else 'read_only'


ENT_STATES = ('live', 'read_only', 'locked')
_LOCKED_MSG = ('Your subscription ended more than 30 days ago and this '
               'workspace is locked. Your data is kept; renew to open it again.')
_READ_ONLY_MSG = ('Your subscription has ended. Your books are read-only until '
                  'you renew; you can still view and export everything.')


def org_allows(ent: dict, feature_key: str, model: AppModel) -> bool:
    """Is the company entitled to `feature_key`? A key removed or added for the company
    wins over its bundles; platform keys are judged by role alone (True here)."""
    if feature_key in (ent.get('rm') or ()):
        return False
    if feature_key in (ent.get('add') or ()):
        return True
    bundle = model.bundle_for_key(feature_key)
    if bundle == PLATFORM:
        return True
    return bundle is not None and bundle in (ent.get('b') or ())


def org_limit(ent: Optional[dict], limit_key: str) -> Optional[int]:
    """The company's quota for `limit_key`; None = unlimited (absent or null)."""
    return ((ent or {}).get('lim') or {}).get(limit_key)


def quota_refusal(ent: Optional[dict], limit_key: str, used: int, adding: int = 1,
                  subscribe_url: Optional[str] = None) -> Optional[Refusal]:
    """QUOTA_EXCEEDED when `used + adding` would pass the company's limit, else None."""
    allowed = org_limit(ent, limit_key)
    if allowed is None or used + adding <= allowed:
        return None
    extra = {'limit': limit_key, 'used': used, 'allowed': allowed}
    if subscribe_url:
        extra['subscribe_url'] = subscribe_url
    return Refusal(reasons.QUOTA_EXCEEDED, 402, f'Your plan allows {allowed:,} and {used:,} are used.',
                   'Upgrade your plan on 3v3 for more.', extra)


def _ent_refusal(ent: dict, keys, method, path, model: AppModel, subscribe_url) -> Optional[Refusal]:
    extra = {'subscribe_url': subscribe_url} if subscribe_url else {}
    st = ent.get('st') or 'live'
    if st not in ENT_STATES:
        return Refusal(reasons.unknown('entitlement state ' + st), 402,
                       f"Your organization's subscription is {st}.", 'Check your plan on 3v3.')
    if st == 'locked':
        if model.is_export(path):
            return None
        return Refusal(reasons.ORG_LOCKED, 402, _LOCKED_MSG, 'Renew your plan on 3v3.', extra)
    if st == 'read_only' and model.is_write(method, path):
        return Refusal(reasons.ORG_READ_ONLY, 402, _READ_ONLY_MSG, 'Renew your plan on 3v3.', extra)
    if any(org_allows(ent, k, model) for k in keys):
        return None
    return Refusal(reasons.PLAN_FEATURE, 402, 'Your plan does not include this feature.',
                   'Upgrade your plan on 3v3 to use it.', extra)


def _plan_refusal(person: Person, keys, method, path, model: AppModel, now, subscribe_url) -> Optional[Refusal]:
    if person.ent is not None:
        return _ent_refusal(person.ent, keys, method, path, model, subscribe_url)
    if not person.plan_key:
        return None                                   # no org plan: no plan restriction
    extra = {'subscribe_url': subscribe_url} if subscribe_url else {}
    bundles = model.plan_bundles(person.plan_key)
    if bundles is None:
        return Refusal(reasons.unknown('plan ' + person.plan_key), 402,
                       f"Your organization's plan ({person.plan_key}) is not recognised.", 'Contact support.')
    status = (person.plan_status or '').lower()
    if status in LAPSED:
        if lapse_stage(person.plan_lapsed_since, now) == 'locked':
            if model.is_export(path):
                return None
            return Refusal(reasons.ORG_LOCKED, 402, _LOCKED_MSG, 'Renew your plan on 3v3.', extra)
        if model.is_write(method, path):
            return Refusal(reasons.ORG_READ_ONLY, 402, _READ_ONLY_MSG, 'Renew your plan on 3v3.', extra)
    elif status not in LIVE:
        return Refusal(reasons.unknown('plan status ' + status), 402,
                       f"Your organization's subscription is {status or 'in an unknown state'}.", 'Check your plan on 3v3.')
    bundles = set(bundles)
    owned = [(k, model.bundle_for_key(k)) for k in keys]
    if any(b == PLATFORM for _k, b in owned):
        return None                                    # platform keys are judged by role alone
    if any(b in bundles for _k, b in owned if b is not None):
        return None
    return Refusal(reasons.PLAN_FEATURE, 402, f'Your plan ({person.plan_key}) does not include this feature.',
                   'Upgrade your plan on 3v3 to use it.', extra)


def decide(person: Optional[Person], workspace: Optional[WorkspaceAccess], feature_keys: Iterable[str],
           method: str, path: str, model: AppModel, workspace_required: bool = True,
           now: Optional[datetime] = None, subscribe_url: Optional[str] = None) -> Decision:
    """May `person` do any one of `feature_keys` here? Refuse at the first failing check."""
    keys = list(feature_keys)
    now = now or datetime.now(timezone.utc)
    write = model.is_write(method, path)

    # 1 caller
    if person is None:
        return Decision.no(Refusal(reasons.NO_CALLER, 401, 'Sign in to continue.', 'Sign in.'))
    platform = person.platform_role in ('platform-admin', 'support')

    # 2 org
    if person.org_id is None and not platform and workspace is None and workspace_required:
        return Decision.no(Refusal(reasons.NO_ORG, 403, 'You are not part of an organization yet.',
                                   'Create or join an organization on 3v3.'))

    # 3 plan (platform staff are not plan-limited)
    if not platform:
        refusal = _plan_refusal(person, keys, method, path, model, now, subscribe_url)
        if refusal:
            return Decision.no(refusal)

    # 4 workspace
    if workspace_required and workspace is None:
        return Decision.no(Refusal(reasons.NO_WORKSPACE_ACCESS, 403, 'You do not have access to this workspace.',
                                   'Ask its owner for access.'))

    # 5 state
    if workspace is not None:
        if workspace.status not in ('ready', 'suspended'):
            return Decision.no(Refusal(reasons.WORKSPACE_UNAVAILABLE, 409, 'This workspace is not available.',
                                       'Choose another, or ask an owner to restore it.'))
        if workspace.status == 'suspended' and write:
            return Decision.no(Refusal(reasons.WORKSPACE_READ_ONLY, 403, 'This workspace is suspended (read-only).',
                                       'Ask its owner to resume it.'))

    # 6 feature: the workspace role if Eve set one, else the role the org role gives
    role = (workspace.app_role if workspace else None) or model.default_role(person.org_role)
    level = workspace.level if workspace else None
    if level == 'viewer' and write:
        return Decision.no(Refusal(reasons.WORKSPACE_READ_ONLY, 403,
                                   'You have view-only access to this workspace.', 'Ask its owner for edit access.'))
    if person.platform_role == 'platform-admin' and workspace is not None:
        return Decision.ok(role='platform-admin', level=level)
    held = list(model.role_keys(role)) if role else []
    if any(covers(held, k) for k in keys):
        return Decision.ok(role=role, level=level)
    return Decision.no(Refusal(reasons.FEATURE_ACCESS_DENIED, 403,
                               f'Access to "{keys[0] if keys else ""}" is not granted.' if len(keys) == 1
                               else f'Access to at least one of "{", ".join(keys)}" is required.',
                               'Ask your organization owner for this permission.'))
