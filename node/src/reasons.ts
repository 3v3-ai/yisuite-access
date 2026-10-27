// Stable refusal codes and one body shape, shared by every app and by the frontend.
export const NO_CALLER = 'NO_CALLER';
export const NO_ORG = 'NO_ORG';
export const NO_APP_ACCESS = 'NO_APP_ACCESS';
export const ORG_READ_ONLY = 'ORG_READ_ONLY';
export const ORG_LOCKED = 'ORG_LOCKED';
export const PLAN_FEATURE = 'PLAN_FEATURE';
export const SEAT_LIMIT = 'SEAT_LIMIT';
export const QUOTA_EXCEEDED = 'QUOTA_EXCEEDED';
export const NO_WORKSPACE_ACCESS = 'NO_WORKSPACE_ACCESS';
export const WORKSPACE_READ_ONLY = 'WORKSPACE_READ_ONLY';
export const WORKSPACE_UNAVAILABLE = 'WORKSPACE_UNAVAILABLE';
export const FEATURE_ACCESS_DENIED = 'FEATURE_ACCESS_DENIED';

export const unknown = (thing: string): string =>
  'UNKNOWN_' + thing.replace(/[^A-Za-z0-9]/g, '_').toUpperCase();

export interface Refusal {
  code: string;
  status: number;
  message: string;
  nextAction?: string;
  extra?: Record<string, unknown>;
}

export const refusalBody = (r: Refusal) => ({
  success: false, error: r.message, error_code: r.code,
  ...(r.nextAction ? { next_action: r.nextAction } : {}), ...(r.extra ?? {}),
});
