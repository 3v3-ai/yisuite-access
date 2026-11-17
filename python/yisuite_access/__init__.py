"""yisuite-access: one way for every Yisuite app to decide who may do what.

Eve decides (who the person is, which org they act for, what the org's plan allows, which
workspaces they may open); this library makes that decision inside an app, the same way in
every app. An app declares only its own features, roles and plan bundles (an AppModel).
"""

from .decision import AppModel, Decision, Person, WorkspaceAccess, decide, org_allows, org_limit, quota_refusal
from .keys import covers
from .reasons import Refusal
from .client import EveClient, EveUnavailable
from .tokens import EnvVerifier, EveClaims, TokenVerifier, bearer, ent_from_claims, looks_like_rs256

__all__ = ['AppModel', 'Decision', 'Person', 'WorkspaceAccess', 'decide', 'covers', 'Refusal',
           'org_allows', 'org_limit', 'quota_refusal', 'ent_from_claims', 'EveClient', 'EveUnavailable',
           'EnvVerifier', 'EveClaims', 'TokenVerifier', 'bearer', 'looks_like_rs256']
__version__ = '0.1.0'
