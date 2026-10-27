// An app calling Eve as a registered service client.
export class EveUnavailable extends Error {}

export interface EveClientLike {
  accessFor(userId: number, orgId?: number | null): Promise<any | null>;
  redeem(code: string): Promise<{ token: string } | null>;
}

export class EveClient implements EveClientLike {
  constructor(private base: string, private secret: string, private timeoutMs = 8000,
              private fetchImpl: typeof fetch = fetch) { this.base = base.replace(/\/$/, ''); }

  private async req(method: string, path: string, body?: unknown) {
    if (!this.secret) throw new EveUnavailable('no service-client secret configured');
    try {
      return await this.fetchImpl(this.base + path, {
        method, signal: AbortSignal.timeout(this.timeoutMs),
        headers: { Authorization: `Bearer ${this.secret}`, 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (e: any) { throw new EveUnavailable(`Eve unreachable: ${e?.message || e}`); }
  }

  async accessFor(userId: number, orgId?: number | null) {
    const r = await this.req('GET', `/api/access/users/${Math.trunc(userId)}${orgId ? `?org_id=${orgId}` : ''}`);
    if (r.status === 404) return null;
    if (r.status >= 400) throw new EveUnavailable(`Eve answered ${r.status}`);
    return r.json();
  }

  async redeem(code: string) {
    const r = await this.req('POST', '/api/handoff/redeem', { code });
    if (r.status === 400 || r.status === 401) return null;
    if (r.status >= 400) throw new EveUnavailable(`Eve answered ${r.status}`);
    return (await r.json()) as { token: string };
  }
}
