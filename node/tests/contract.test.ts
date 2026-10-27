import { readFileSync } from 'fs';
import { resolve } from 'path';
import { isDeepStrictEqual } from 'util';
import { describe, expect, it } from 'vitest';
import { covers, decide, TableModel } from '../src';

const dir = resolve(__dirname, '../../contracts');
const vectors = JSON.parse(readFileSync(resolve(dir, 'key_cover_cases.json'), 'utf8')).cases as
  { held: string[]; want: string; parent: string | null; expect: boolean; why: string }[];
const doc = JSON.parse(readFileSync(resolve(dir, 'decision_cases.json'), 'utf8'));
const model = new TableModel(doc.model);

describe('key covers: the shared vectors (also run by Python)', () => {
  for (const c of vectors) it(c.why, () => expect(covers(c.held, c.want, c.parent)).toBe(c.expect));
});

describe(`decision: ${doc.cases.length} cases generated from the Python reference`, () => {
  // One test with a clear failure list is more useful than 1,152 separate tests.
  it('reaches exactly the same decision for every case', () => {
    const wrong: string[] = [];
    for (const c of doc.cases) {
      const d = decide(c.person, c.workspace, c.keys, c.method, c.path, model, { now: new Date(c.now) });
      const got = { allowed: d.allowed, code: d.code, status: d.refusal?.status ?? null, role: d.role, level: d.level };
      if (!isDeepStrictEqual(got, c.expect)) {
        wrong.push(`${c.name}: expected ${JSON.stringify(c.expect)} got ${JSON.stringify(got)}`);
      }
    }
    expect(wrong.slice(0, 10)).toEqual([]);
    expect(wrong).toHaveLength(0);
  });
});
