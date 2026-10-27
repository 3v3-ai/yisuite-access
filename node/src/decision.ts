// The access decision: six checks, first refusal wins, anything unknown is a no.
// Port of python/yisuite_access/decision.py; contracts/decision_cases.json holds the cases both pass.
import { covers } from './keys';
import * as R from './reasons';
import { Refusal } from './reasons';

export const PLATFORM = 'platform';
export const READ_ONLY_DAYS = 30;
const LIVE = ['trialing', 'active', 'past_due'];
const LAPSED = ['expired', 'canceled', 'cancelled'];

/** What an app declares about itself. */
export interface AppModel {
  bundleForKey(featureKey: string): string | null;
  planBundles(planKey: string): Iterable<string> | null;
  roleKeys(roleName: string): Iterable<string>;
  defaultRole(orgRole: string | null | undefined): string | null;
  isWrite(method: string, path: string): boolean;
  isExport(path: string): boolean;
}

export interface Person {
  user_id: number;
  email?: string;
  platform_role?: string | null;
  org_id?: number | null;
  org_type?: string | null;
  org_role?: string | null;
  plan_key?: string | null;
  plan_status?: string | null;
  plan_lapsed_since?: Date | string | null;
}

export interface WorkspaceAccess {
  key: string;
  level?: 'owner' | 'editor' | 'viewer' | string;
  status?: string;
  app_role?: string | null;
  data_window?: { from: string | null; to: string | null } | null;
}

export interface Decision {
  allowed: boolean;
  code: string | null;
  refusal: Refusal | null;
  role: string | null;
  level: string | null;
}

const ok = (role: string | null = null, level: string | null = null): Decision =>
  ({ allowed: true, code: null, refusal: null, role, level });
const no = (refusal: Refusal): Decision =>
  ({ allowed: false, code: refusal.code, refusal, role: null, level: null });

export function lapseStage(since: Date | string | null | undefined, now: Date): 'read_only' | 'locked' {
  if (!since) return 'read_only';                // an unknown date is never locked on a guess
  const s = since instanceof Date ? since : new Date(since);
  return now.getTime() >= s.getTime() + READ_ONLY_DAYS * 86_400_000 ? 'locked' : 'read_only';
}

function planRefusal(p: Person, keys: string[], method: string, path: string, model: AppModel,
                     now: Date, subscribeUrl?: string): Refusal | null {
  if (!p.plan_key) return null;                  // no org plan: no plan restriction
  const extra = subscribeUrl ? { subscribe_url: subscribeUrl } : {};
  const bundles = model.planBundles(p.plan_key);
  if (bundles === null || bundles === undefined) {
    return { code: R.unknown('plan ' + p.plan_key), status: 402,
             message: `Your organization's plan (${p.plan_key}) is not recognised.`, nextAction: 'Contact support.' };
  }
  const status = (p.plan_status || '').toLowerCase();
  if (LAPSED.includes(status)) {
    if (lapseStage(p.plan_lapsed_since, now) === 'locked') {
      if (model.isExport(path)) return null;
      return { code: R.ORG_LOCKED, status: 402, extra,
               message: 'Your subscription ended more than 30 days ago and this workspace is locked. Your data is kept; renew to open it again.',
               nextAction: 'Renew your plan on 3v3.' };
    }
    if (model.isWrite(method, path)) {
      return { code: R.ORG_READ_ONLY, status: 402, extra,
               message: 'Your subscription has ended. Your books are read-only until you renew; you can still view and export everything.',
               nextAction: 'Renew your plan on 3v3.' };
    }
  } else if (!LIVE.includes(status)) {
    return { code: R.unknown('plan status ' + status), status: 402,
             message: `Your organization's subscription is ${status || 'in an unknown state'}.`, nextAction: 'Check your plan on 3v3.' };
  }
  const have = new Set(bundles);
  const owned = keys.map(k => model.bundleForKey(k));
  if (owned.some(b => b === PLATFORM)) return null;       // platform keys are judged by role alone
  if (owned.some(b => b !== null && have.has(b))) return null;
  return { code: R.PLAN_FEATURE, status: 402, extra,
           message: `Your plan (${p.plan_key}) does not include this feature.`, nextAction: 'Upgrade your plan on 3v3 to use it.' };
}

export interface DecideOptions { workspaceRequired?: boolean; now?: Date; subscribeUrl?: string }

export function decide(person: Person | null, workspace: WorkspaceAccess | null, featureKeys: string[],
                       method: string, path: string, model: AppModel, opts: DecideOptions = {}): Decision {
  const keys = [...featureKeys];
  const now = opts.now ?? new Date();
  const workspaceRequired = opts.workspaceRequired ?? true;
  const write = model.isWrite(method, path);

  // 1 caller
  if (!person) return no({ code: R.NO_CALLER, status: 401, message: 'Sign in to continue.', nextAction: 'Sign in.' });
  const platform = person.platform_role === 'platform-admin' || person.platform_role === 'support';

  // 2 org
  if ((person.org_id === null || person.org_id === undefined) && !platform && !workspace && workspaceRequired) {
    return no({ code: R.NO_ORG, status: 403, message: 'You are not part of an organization yet.',
                nextAction: 'Create or join an organization on 3v3.' });
  }

  // 3 plan (platform staff are not plan-limited)
  if (!platform) {
    const refusal = planRefusal(person, keys, method, path, model, now, opts.subscribeUrl);
    if (refusal) return no(refusal);
  }

  // 4 workspace
  if (workspaceRequired && !workspace) {
    return no({ code: R.NO_WORKSPACE_ACCESS, status: 403, message: 'You do not have access to this workspace.',
                nextAction: 'Ask its owner for access.' });
  }

  // 5 state
  const status = workspace?.status ?? 'ready';
  if (workspace) {
    if (status !== 'ready' && status !== 'suspended') {
      return no({ code: R.WORKSPACE_UNAVAILABLE, status: 409, message: 'This workspace is not available.',
                  nextAction: 'Choose another, or ask an owner to restore it.' });
    }
    if (status === 'suspended' && write) {
      return no({ code: R.WORKSPACE_READ_ONLY, status: 403, message: 'This workspace is suspended (read-only).',
                  nextAction: 'Ask its owner to resume it.' });
    }
  }

  // 6 feature: the workspace role if Eve set one, else the role the org role gives
  const role = workspace?.app_role || model.defaultRole(person.org_role);
  const level = workspace ? (workspace.level ?? 'editor') : null;
  if (level === 'viewer' && write) {
    return no({ code: R.WORKSPACE_READ_ONLY, status: 403, message: 'You have view-only access to this workspace.',
                nextAction: 'Ask its owner for edit access.' });
  }
  if (person.platform_role === 'platform-admin' && workspace) return ok('platform-admin', level);
  const held = role ? [...model.roleKeys(role)] : [];
  if (keys.some(k => covers(held, k))) return ok(role ?? null, level);
  return no({ code: R.FEATURE_ACCESS_DENIED, status: 403,
              message: keys.length === 1 ? `Access to "${keys[0] ?? ''}" is not granted.`
                                         : `Access to at least one of "${keys.join(', ')}" is required.`,
              nextAction: 'Ask your organization owner for this permission.' });
}
