// Verify Eve's v2 access tokens: RS256, one audience, public keys from Eve's JWKS.
import { createRemoteJWKSet, jwtVerify, JWTPayload } from 'jose';
import { Entitlement, Person } from './decision';

export const DEFAULT_ISSUER = 'https://api.3v3.ai';

export interface Verifier { verify(token: string): Promise<JWTPayload> }

export function remoteVerifier(appSlug: string, jwksUrl: string, issuer = DEFAULT_ISSUER): Verifier {
  const keys = createRemoteJWKSet(new URL(jwksUrl), { cacheMaxAge: 600_000 });
  return {
    async verify(token: string) {
      const { payload } = await jwtVerify(token, keys, {
        algorithms: ['RS256'], audience: appSlug, issuer, requiredClaims: ['exp', 'iat', 'sub', 'aud', 'iss'] });
      return payload;
    },
  };
}

export const ENT_VERSION = 1;

/** This app's entitlement from the token (`ent` keyed by the audience app), or null. */
export function entFromClaims(c: JWTPayload & Record<string, any>): Entitlement | null {
  if (c.entv !== ENT_VERSION) return null;
  const app = Array.isArray(c.aud) ? (c.aud.length === 1 ? c.aud[0] : null) : c.aud;
  const ent = typeof app === 'string' ? c.ent?.[app] : null;
  return ent && typeof ent === 'object' ? ent as Entitlement : null;
}

export function personFromClaims(c: JWTPayload & Record<string, any>, lapsedSince?: Date | null): Person {
  const org = c.org ?? {};
  const plan = c.plan ?? {};
  return { user_id: Number(c.sub), email: c.email ?? '', platform_role: c.plat ?? null, org_id: org.id ?? null,
           org_type: org.type ?? null, org_role: org.role ?? null, plan_key: plan.key ?? null,
           plan_status: plan.status ?? null, plan_lapsed_since: lapsedSince ?? null, ent: entFromClaims(c) };
}

export function lapsedSinceFromDocument(doc: any): Date | null {
  const raw = doc?.plan?.ends_at;
  if (!raw) return null;
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? null : d;
}
