// Eve's signed change events: verify, apply once.
import crypto from 'crypto';

export function signatureOk(secret: string, body: Buffer | string, header: string | undefined): boolean {
  if (!secret || !header) return false;
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
  const a = Buffer.from(header); const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/** At-least-once delivery means repeats: remember the last N event ids. */
export class Dedupe {
  private seen = new Map<number, true>();
  constructor(private size = 5000) {}
  firstTime(id: unknown): boolean {
    const n = Number(id);
    if (!Number.isInteger(n)) return true;
    if (this.seen.has(n)) { this.seen.delete(n); this.seen.set(n, true); return false; }
    this.seen.set(n, true);
    if (this.seen.size > this.size) this.seen.delete(this.seen.keys().next().value as number);
    return true;
  }
  forget(id: unknown) { this.seen.delete(Number(id)); }
}
