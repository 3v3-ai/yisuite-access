import { readFileSync } from 'fs';
import { resolve } from 'path';
import { describe, expect, it } from 'vitest';
import { entFromClaims, orgAllows, orgLimit, personFromClaims, quotaRefusal, TableModel } from '../src';

const model = new TableModel(JSON.parse(readFileSync(resolve(__dirname, '../../contracts/decision_cases.json'), 'utf8')).model);
const ENT = { b: ['core'], add: ['ai.assistant'], rm: ['tickets.view'], lim: { tickets_per_month: 100, seats: null }, cat: 'h', st: 'live' };

describe('entitlement helpers (same answers as the Python reference)', () => {
  it('orgAllows: bundles, added and removed keys, platform keys', () => {
    expect(orgAllows(ENT, 'tickets.list', model)).toBe(true);
    expect(orgAllows(ENT, 'tickets.view', model)).toBe(false);
    expect(orgAllows(ENT, 'ai.assistant', model)).toBe(true);
    expect(orgAllows(ENT, 'banking.import', model)).toBe(false);
    expect(orgAllows(ENT, 'admin.tenants', model)).toBe(true);
  });
  it('orgLimit and quotaRefusal', () => {
    expect(orgLimit(ENT, 'tickets_per_month')).toBe(100);
    expect(orgLimit(ENT, 'seats')).toBeNull();
    expect(orgLimit(null, 'x')).toBeNull();
    expect(quotaRefusal(ENT, 'tickets_per_month', 99)).toBeNull();
    const r = quotaRefusal(ENT, 'tickets_per_month', 100, 1, 'https://3v3.ai/billing')!;
    expect(r).toMatchObject({ code: 'QUOTA_EXCEEDED', status: 402, extra: { allowed: 100, used: 100 } });
  });
  it('entFromClaims reads the audience app and the version', () => {
    const c: any = { sub: '1', aud: 'yiflow', entv: 1, ent: { yiflow: ENT } };
    expect(entFromClaims(c)).toEqual(ENT);
    expect(entFromClaims({ ...c, aud: ['yiflow'] })).toEqual(ENT);
    expect(entFromClaims({ ...c, entv: 2 })).toBeNull();
    expect(personFromClaims(c).ent).toEqual(ENT);
  });
});
