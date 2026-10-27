// Express adapter: default-deny gate, the decision, events, hand-off.
//
//   const access = new YisuiteAccess({ appSlug: 'yimport', eveUrl, clientSecret, webhookSecret, model, public: ['/health'] });
//   app.use(access.routes());                     // /_yisuite/handoff, /_yisuite/events, /_yisuite/logout
//   app.use(access.gate());                       // every other route needs a signed-in person
//   app.get('/jobs', access.require({ feature: 'jobs.list', workspace: req => String(req.query.company) }), handler);
//
// A route is never open by default: it is listed in `public`, or it needs a person.
import crypto from 'crypto';
import express, { NextFunction, Request, RequestHandler, Response, Router } from 'express';
import { EveClient, EveClientLike, EveUnavailable } from './client';
import { AppModel, decide, Decision, Person, WorkspaceAccess } from './decision';
import { Dedupe, signatureOk } from './events';
import * as R from './reasons';
import { refusalBody, Refusal } from './reasons';
import { DEFAULT_ISSUER, lapsedSinceFromDocument, personFromClaims, remoteVerifier, Verifier } from './tokens';

export const COOKIE = 'ys_token';

export interface Options {
  appSlug: string; eveUrl: string; model: AppModel; clientSecret?: string; webhookSecret?: string;
  issuer?: string; loginUrl?: string; subscribeUrl?: string; verifier?: Verifier; client?: EveClientLike;
  public?: (string | RegExp)[]; docTtlMs?: number; staleOkMs?: number; secureCookie?: boolean;
}

declare global { namespace Express { interface Request { ysPerson?: Person | null; ysDecision?: Decision } } }

const readCookie = (req: Request, name: string): string | undefined => {
  for (const part of (req.headers.cookie || '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return undefined;
};

export class YisuiteAccess {
  private verifier: Verifier;
  private client: EveClientLike;
  private dedupe = new Dedupe();
  private docs = new Map<string, { at: number; doc: any }>();
  private docTtl: number; private staleOk: number;

  constructor(private o: Options) {
    this.verifier = o.verifier ?? remoteVerifier(o.appSlug, `${o.eveUrl.replace(/\/$/, '')}/.well-known/jwks.json`, o.issuer ?? DEFAULT_ISSUER);
    this.client = o.client ?? new EveClient(o.eveUrl, o.clientSecret ?? '');
    this.docTtl = o.docTtlMs ?? 30_000; this.staleOk = o.staleOkMs ?? 600_000;
  }

  private isPublic(path: string) {
    return (this.o.public ?? []).some(p => (typeof p === 'string' ? p === path : p.test(path)));
  }

  /** The verified person for this request (cached on req), or null. */
  async person(req: Request): Promise<Person | null> {
    if (req.ysPerson !== undefined) return req.ysPerson;
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7).trim() : readCookie(req, COOKIE);
    let person: Person | null = null;
    if (token) {
      try { person = personFromClaims(await this.verifier.verify(token) as any); } catch { person = null; }
    }
    req.ysPerson = person;
    return person;
  }

  private async document(p: Person) {
    const key = `${p.user_id}:${p.org_id ?? ''}`;
    const hit = this.docs.get(key);
    const now = Date.now();
    if (hit && now - hit.at < this.docTtl) return hit.doc;
    try {
      const doc = await this.client.accessFor(p.user_id, p.org_id);
      this.docs.set(key, { at: now, doc });
      return doc;
    } catch (e) {
      if (e instanceof EveUnavailable && hit && now - hit.at < this.staleOk) return hit.doc;   // stale beats locked out
      throw e;
    }
  }

  async decideFor(req: Request, featureKeys: string[], workspaceKey?: string | null, workspaceRequired = true): Promise<Decision> {
    const person = await this.person(req);
    if (!person) return decide(null, null, featureKeys, req.method, req.path, this.o.model);
    let doc: any; let ws: WorkspaceAccess | null = null;
    try {
      doc = (await this.document(person)) ?? {};
      const found = (doc.workspaces ?? []).find((w: any) => String(w.key).toLowerCase() === String(workspaceKey ?? '').toLowerCase());
      ws = workspaceKey && found ? { key: found.key, level: found.level, status: found.status, app_role: found.app_role, data_window: found.data_window } : null;
    } catch {
      return { allowed: false, code: R.NO_CALLER, role: null, level: null,
               refusal: { code: R.NO_CALLER, status: 503, message: 'Access could not be checked right now.', nextAction: 'Try again shortly.' } };
    }
    return decide({ ...person, plan_lapsed_since: lapsedSinceFromDocument(doc) }, ws, featureKeys, req.method, req.path,
                  this.o.model, { workspaceRequired, subscribeUrl: this.o.subscribeUrl });
  }

  private refuse(req: Request, res: Response, r: Refusal) {
    if (r.status === 401 && req.method === 'GET' && (req.headers.accept || '').includes('text/html')) {
      return res.redirect(this.o.loginUrl ?? 'https://www.3v3.ai/login');
    }
    return res.status(r.status).json(refusalBody(r));
  }

  /** Default-deny: every route not listed as public needs a verified person. */
  gate(): RequestHandler {
    return async (req, res, next) => {
      if (req.method === 'OPTIONS' || this.isPublic(req.path)) return next();
      if (await this.person(req)) return next();
      return this.refuse(req, res, { code: R.NO_CALLER, status: 401, message: 'Sign in to continue.', nextAction: 'Sign in.' });
    };
  }

  require(opts: { feature: string | string[]; workspace?: (req: Request) => string | null | undefined }): RequestHandler {
    const keys = Array.isArray(opts.feature) ? opts.feature : [opts.feature];
    return async (req, res, next) => {
      const d = await this.decideFor(req, keys, opts.workspace ? opts.workspace(req) : null, !!opts.workspace);
      if (!d.allowed) return this.refuse(req, res, d.refusal!);
      req.ysDecision = d;
      next();
    };
  }

  routes(): Router {
    const r = express.Router();
    r.post('/_yisuite/handoff', express.json(), async (req: Request, res: Response) => {
      const code = String(req.body?.code ?? '').trim();
      if (!code) return res.status(400).json({ success: false, error: 'code is required' });
      try {
        const out = await this.client.redeem(code);
        if (!out?.token) {
          return res.status(401).json({ success: false, error_code: 'HANDOFF_REFUSED',
            error: 'The sign-in link was already used or has expired. Open the app again from 3v3.' });
        }
        res.cookie(COOKIE, out.token, { httpOnly: true, sameSite: 'lax', secure: this.o.secureCookie ?? true, maxAge: 15 * 60_000 });
        return res.json({ success: true });
      } catch (e: any) {
        return res.status(503).json({ success: false, error_code: 'EVE_UNAVAILABLE', error: String(e?.message || e) });
      }
    });
    r.post('/_yisuite/events', express.raw({ type: '*/*', limit: '1mb' }), (req: Request, res: Response) => {
      const body: Buffer = Buffer.isBuffer(req.body) ? req.body : Buffer.from('');
      if (!signatureOk(this.o.webhookSecret ?? '', body, req.headers['x-yisuite-signature'] as string | undefined)) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
      }
      let data: any = {};
      try { data = JSON.parse(body.toString('utf8')); } catch { /* an empty or odd body is still acknowledged once */ }
      if (!this.dedupe.firstTime(data.id)) return res.json({ success: true, duplicate: true });
      this.docs.clear();                                    // something about someone changed: ask Eve again
      return res.json({ success: true });
    });
    r.post('/_yisuite/logout', (_req: Request, res: Response) => { res.clearCookie(COOKIE); res.json({ success: true }); });
    return r;
  }
}
