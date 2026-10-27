import crypto from 'crypto';
import express from 'express';
import http from 'http';
import { AddressInfo } from 'net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EveUnavailable, TableModel, YisuiteAccess } from '../src';
import { readFileSync } from 'fs';
import { resolve } from 'path';

const model = new TableModel(JSON.parse(readFileSync(resolve(__dirname, '../../contracts/decision_cases.json'), 'utf8')).model);

// A stand-in for Eve's tokens: the token text is the user id; 'bad' is refused.
const verifier = { async verify(t: string) {
  if (t === 'bad') throw new Error('bad token');
  const uid = Number(t);
  return { sub: String(uid), email: `u${uid}@x`, org: { id: 5, type: 'client', role: uid === 1 ? 'owner' : 'member' },
           plan: { key: 'standard', status: 'active' }, plat: null } as any;
} };

const state = { calls: 0, down: false };
const client = {
  async accessFor(uid: number) {
    state.calls++;
    if (state.down) throw new EveUnavailable('down');
    return { 1: { workspaces: [{ key: 'acme', level: 'owner', status: 'ready' }] },
             2: { workspaces: [{ key: 'acme', level: 'viewer', status: 'ready' }] } }[uid as 1 | 2] ?? null;
  },
  async redeem(code: string) { return code === 'good' ? { token: '1' } : null; },
};

let server: http.Server; let base = ''; let access: YisuiteAccess;

beforeAll(async () => {
  access = new YisuiteAccess({ appSlug: 'yimport', eveUrl: 'https://eve.test', model, webhookSecret: 'wh', verifier, client,
                               public: ['/health'], secureCookie: false });
  const app = express();
  app.use(access.routes());
  app.use(access.gate());
  app.get('/health', (_q, r) => { r.send('ok'); });
  app.get('/open', (_q, r) => { r.send('signed in'); });
  const ws = (req: express.Request) => String(req.query.company ?? '');
  app.get('/tickets', access.require({ feature: 'tickets.list', workspace: ws }), (_q, r) => { r.send('list'); });
  app.post('/tickets', access.require({ feature: 'tickets.create', workspace: ws }), (_q, r) => { r.send('created'); });
  server = http.createServer(app);
  await new Promise<void>(r => server.listen(0, r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>(r => server.close(() => r())));

const call = (method: string, path: string, headers: Record<string, string> = {}, body?: unknown) =>
  fetch(base + path, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body ? JSON.stringify(body) : undefined, redirect: 'manual' });
const auth = (u: number | string) => ({ Authorization: `Bearer ${u}` });

describe('the gate', () => {
  it('lets public paths through and needs a signed-in person elsewhere', async () => {
    expect((await call('GET', '/health')).status).toBe(200);
    expect((await call('GET', '/open')).status).toBe(401);
    expect((await call('GET', '/open', auth(1))).status).toBe(200);
    expect((await call('GET', '/open', auth('bad'))).status).toBe(401);
  });
  it('sends a browser to sign in instead of showing JSON', async () => {
    const r = await call('GET', '/open', { Accept: 'text/html' });
    expect(r.status).toBe(302); expect(r.headers.get('location')).toContain('login');
  });
});

describe('require(): the decision with Eve\'s workspace and level', () => {
  it('decides by workspace', async () => {
    expect((await call('GET', '/tickets?company=acme', auth(1))).status).toBe(200);
    expect((await (await call('GET', '/tickets?company=other', auth(1))).json()).error_code).toBe('NO_WORKSPACE_ACCESS');
    expect((await (await call('GET', '/tickets', auth(1))).json()).error_code).toBe('NO_WORKSPACE_ACCESS');
  });
  it('a viewer reads but does not write', async () => {
    expect((await call('GET', '/tickets?company=acme', auth(2))).status).toBe(200);
    const r = await call('POST', '/tickets?company=acme', auth(2));
    expect(r.status).toBe(403); expect((await r.json()).error_code).toBe('WORKSPACE_READ_ONLY');
    expect((await call('POST', '/tickets?company=acme', auth(1))).status).toBe(200);
  });
  it('caches Eve\'s document and serves a stale one if Eve is down, but never allows on no answer', async () => {
    state.calls = 0;
    await call('GET', '/tickets?company=acme', auth(1)); await call('GET', '/tickets?company=acme', auth(1));
    expect(state.calls).toBeLessThanOrEqual(1);
    (access as any).docs.clear();
    state.down = true;
    expect((await call('GET', '/tickets?company=acme', auth(1))).status).toBe(503);        // no history: never an allow
    state.down = false;
    await call('GET', '/tickets?company=acme', auth(1));
    state.down = true; (access as any).docTtl = 0;
    expect((await call('GET', '/tickets?company=acme', auth(1))).status).toBe(200);        // stale beats locked out
    state.down = false; (access as any).docTtl = 30_000;
  });
});

describe('events and hand-off', () => {
  const sig = (body: string) => 'sha256=' + crypto.createHmac('sha256', 'wh').update(body).digest('hex');
  it('applies a signed event once, refuses a bad signature, and drops the cache', async () => {
    const body = JSON.stringify({ id: 9, topic: 'grant.changed' });
    const post = (s: string) => fetch(base + '/_yisuite/events', { method: 'POST', body, headers: { 'Content-Type': 'application/json', 'X-Yisuite-Signature': s } });
    expect((await post(sig(body))).status).toBe(200);
    expect((await (await post(sig(body))).json()).duplicate).toBe(true);
    expect((await post('sha256=00')).status).toBe(401);
  });
  it('redeems a one-time code into a cookie', async () => {
    expect((await call('POST', '/_yisuite/handoff', {}, {})).status).toBe(400);
    expect((await call('POST', '/_yisuite/handoff', {}, { code: 'spent' })).status).toBe(401);
    const ok = await call('POST', '/_yisuite/handoff', {}, { code: 'good' });
    expect(ok.status).toBe(200);
    const cookie = ok.headers.get('set-cookie') || '';
    expect(cookie).toContain('ys_token=1'); expect(cookie.toLowerCase()).toContain('httponly');
    expect((await call('GET', '/open', { Cookie: cookie.split(';')[0] })).status).toBe(200);
  });
});
