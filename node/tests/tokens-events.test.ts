import crypto from 'crypto';
import http from 'http';
import { AddressInfo } from 'net';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Dedupe, lapsedSinceFromDocument, personFromClaims, remoteVerifier, signatureOk } from '../src';

let server: http.Server; let jwksUrl = ''; let privateKey: CryptoKey;

beforeAll(async () => {
  const kp = await generateKeyPair('RS256');
  privateKey = kp.privateKey as CryptoKey;
  const jwk = { ...(await exportJWK(kp.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  server = http.createServer((_q, res) => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ keys: [jwk] })); });
  await new Promise<void>(r => server.listen(0, r));
  jwksUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/.well-known/jwks.json`;
});
afterAll(() => new Promise<void>(r => server.close(() => r())));

const sign = (claims: Record<string, unknown> = {}, key: CryptoKey = privateKey, over: { aud?: string; iss?: string; exp?: string } = {}) =>
  new SignJWT({ email: 'm@x.com', org: { id: 5, type: 'client', role: 'owner' }, plan: { key: 'standard', status: 'active' }, plat: null, ...claims })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setSubject('66').setAudience(over.aud ?? 'yimport')
    .setIssuer(over.iss ?? 'https://api.3v3.ai').setIssuedAt().setExpirationTime(over.exp ?? '15m').sign(key);

describe('token verification against a real JWKS endpoint', () => {
  it('accepts a token for this app, issued by Eve', async () => {
    const claims = await remoteVerifier('yimport', jwksUrl).verify(await sign());
    const p = personFromClaims(claims as any);
    expect(p).toMatchObject({ user_id: 66, org_id: 5, org_role: 'owner', plan_key: 'standard', plan_status: 'active' });
  });

  it('refuses another audience, another issuer, an expired token and a foreign key', async () => {
    const v = remoteVerifier('yimport', jwksUrl);
    await expect(v.verify(await sign({}, privateKey, { aud: 'yincome' }))).rejects.toThrow();
    await expect(v.verify(await sign({}, privateKey, { iss: 'https://evil.example' }))).rejects.toThrow();
    await expect(v.verify(await sign({}, privateKey, { exp: '-1m' }))).rejects.toThrow();
    const other = await generateKeyPair('RS256');
    await expect(v.verify(await sign({}, other.privateKey as CryptoKey))).rejects.toThrow();
  });

  it('refuses an HS256 token (algorithm confusion)', async () => {
    const forged = await new SignJWT({}).setProtectedHeader({ alg: 'HS256' }).setSubject('1').setAudience('yimport')
      .setIssuer('https://api.3v3.ai').setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode('any-shared-secret'));
    await expect(remoteVerifier('yimport', jwksUrl).verify(forged)).rejects.toThrow();
  });

  it('reads the lapse date from the access document', () => {
    expect(lapsedSinceFromDocument({ plan: { ends_at: '2026-09-01T00:00:00.000Z' } })?.getUTCFullYear()).toBe(2026);
    expect(lapsedSinceFromDocument({})).toBeNull();
    expect(lapsedSinceFromDocument({ plan: { ends_at: 'garbage' } })).toBeNull();
  });
});

describe('events', () => {
  const sig = (secret: string, body: string) => 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
  it('verifies the signature over the body and the secret', () => {
    expect(signatureOk('s3', '{"id":1}', sig('s3', '{"id":1}'))).toBe(true);
    expect(signatureOk('other', '{"id":1}', sig('s3', '{"id":1}'))).toBe(false);
    expect(signatureOk('s3', '{"id":1} ', sig('s3', '{"id":1}'))).toBe(false);
    expect(signatureOk('', '{}', sig('', '{}'))).toBe(false);
    expect(signatureOk('s3', '{}', undefined)).toBe(false);
  });
  it('applies an event once', () => {
    const d = new Dedupe();
    expect(d.firstTime(5)).toBe(true); expect(d.firstTime(5)).toBe(false);
    d.forget(5); expect(d.firstTime(5)).toBe(true);
  });
});
