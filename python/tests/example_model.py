"""A small AppModel, as an app would write one."""

from yisuite_access.decision import PLATFORM


class ExampleModel:
    PLANS = {'standard': {'core'}, 'premium': {'core', 'ai'}}
    ROLES = {'Owner': ['tickets', 'ai'], 'Member': ['tickets.list']}

    def bundle_for_key(self, key):
        if key.startswith('admin'):
            return PLATFORM
        if key.startswith('tickets'):
            return 'core'
        if key.startswith('ai'):
            return 'ai'
        return None

    def plan_bundles(self, plan_key):
        return self.PLANS.get(plan_key)

    def role_keys(self, role):
        return self.ROLES.get(role, [])

    def default_role(self, org_role):
        return {'owner': 'Owner', 'admin': 'Owner', 'member': 'Member'}.get(org_role or '')

    def is_write(self, method, path):
        return method not in ('GET', 'HEAD', 'OPTIONS') and 'report' not in path and 'export' not in path

    def is_export(self, path):
        return 'export' in path
