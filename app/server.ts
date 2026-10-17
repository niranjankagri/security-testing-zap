/**
 * NoteVault: the web app under test. Node only, no dependencies; Node runs this TypeScript file directly.
 *
 *   node app/server.ts --port 4320                       the hardened build
 *   node app/server.ts --port 4321 --build vulnerable    the same app with the defects of app/defects.ts
 *
 * Add --host 0.0.0.0 only inside a container (the scan scripts do); the default listens on 127.0.0.1.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { parseArgs } from 'node:util';
import { defectsOf, type Build, type DefectId } from './defects.ts';
import { NOT_FOUND_PAGE, expiredPage, homePage, loginPage, notesPage, searchPage } from './pages.ts';
import { Store, type Note } from './store.ts';

const TIPS = [
  'Holiday: write down your booking numbers in a note',
  'Passwords: never keep them in plain notes',
  'Shopping: one list per shop saves time',
];

/** Whether the running build contains a defect. */
type Has = (id: DefectId) => boolean;

const STYLES = 'body { font-family: Arial, sans-serif; max-width: 40rem; margin: 2rem auto; }\n';

/** Headers that every response gets. Each defect removes or adds exactly one protection. */
function securityHeaders(has: Has): Record<string, string> {
  const headers: Record<string, string> = {
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
    'cross-origin-embedder-policy': 'require-corp',
    // Notes are private: no copy in browser or proxy caches.
    'cache-control': 'no-store',
  };
  if (!has('no-csp')) {
    const frames = has('no-clickjacking-protection') ? '' : " frame-ancestors 'none';";
    headers['content-security-policy'] =
      `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none';${frames}`;
  }
  if (!has('no-clickjacking-protection')) headers['x-frame-options'] = 'DENY';
  if (!has('no-nosniff')) headers['x-content-type-options'] = 'nosniff';
  if (has('powered-by-header')) headers['x-powered-by'] = 'NoteVault/0.9 (Node.js 24)';
  return headers;
}

function sessionCookie(id: string, has: Has): string {
  const parts = [`sid=${id}`, 'Path=/', 'Secure'];
  if (!has('cookie-not-httponly')) parts.push('HttpOnly');
  if (!has('cookie-no-samesite')) parts.push('SameSite=Strict');
  return parts.join('; ');
}

function cookieValue(request: IncomingMessage, name: string): string | undefined {
  for (const part of (request.headers.cookie ?? '').split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return value.join('=');
  }
  return undefined;
}

async function readBody(request: IncomingMessage): Promise<string> {
  let body = '';
  for await (const chunk of request) {
    body += String(chunk);
    if (body.length > 10_000) throw new Error('body too large');
  }
  return body;
}

/** The fields a client may change on a note. Everything else in the request body is ignored. */
const EDITABLE: readonly (keyof Note)[] = ['title', 'text'];

export function createApp(build: Build, store = new Store()): Server {
  const defects = defectsOf(build);
  const has: Has = (id) => defects.has(id);
  const baseHeaders = securityHeaders(has);

  return createServer((request, response) => {
    handle(request, response).catch((error: unknown) => {
      console.error(error);
      // A generic message: stack traces and library names stay in the server log.
      if (!response.headersSent) send(response, 500, 'text/plain; charset=utf-8', 'Something went wrong');
    });
  });

  function send(response: ServerResponse, status: number, type: string, body: string, extra = {}): void {
    response.writeHead(status, { ...baseHeaders, 'content-type': type, ...extra });
    response.end(body);
  }

  function json(response: ServerResponse, status: number, value: unknown): void {
    send(response, status, 'application/json; charset=utf-8', JSON.stringify(value));
  }

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = new URL(request.url ?? '/', 'http://localhost');
    // Only canonical paths: "/%2e/login" or "//login" would be treated as "/login" by the URL parser, the classic
    // way past path-based access rules. Ambiguous requests are refused instead of guessed.
    const rawPath = (request.url ?? '/').split('?')[0] ?? '/';
    if (rawPath !== url.pathname || rawPath.includes('//')) {
      return send(response, 400, 'text/plain; charset=utf-8', 'Bad request');
    }
    const route = `${request.method} ${url.pathname}`;
    const sid = cookieValue(request, 'sid');
    const session = store.session(sid);
    const user = session?.userId ? store.users.find((u) => u.id === session.userId) : undefined;
    const html = 'text/html; charset=utf-8';

    if (route === 'GET /') return send(response, 200, html, homePage());
    if (route === 'GET /styles.css') return send(response, 200, 'text/css; charset=utf-8', STYLES);

    if (route === 'GET /search') {
      const term = url.searchParams.get('q') ?? '';
      const results = TIPS.filter((tip) => tip.toLowerCase().includes(term.toLowerCase()));
      return send(response, 200, html, searchPage(term, term ? results : [], !has('reflected-xss')));
    }

    if (route === 'GET /login') {
      // Every visitor gets a session first: it carries the anti-CSRF token of the login form.
      if (session) return send(response, 200, html, loginPage(session.csrfToken));
      const created = store.createSession();
      return send(response, 200, html, loginPage(created.session.csrfToken), {
        'set-cookie': sessionCookie(created.id, has),
      });
    }

    if (route === 'POST /login') {
      const form = new URLSearchParams(await readBody(request));
      if (!session || !sid || form.get('csrf_token') !== session.csrfToken) {
        // 400, not 403: the request is invalid, not forbidden. With 403, ZAP's "Bypassing 403" rule took /login for a
        // protected path and reported the public GET /login as a bypass. No form on this page: a form here would have
        // no valid token. The link starts a fresh one.
        return send(response, 400, html, expiredPage());
      }
      const name = form.get('name') ?? '';
      if (!has('no-login-rate-limit') && store.isLocked(name)) {
        return send(response, 429, html, loginPage(session.csrfToken, 'Too many attempts. Try again later.'), {
          'retry-after': '900',
        });
      }
      const found = store.authenticate(name, form.get('password') ?? '');
      if (!found) {
        store.recordFailedLogin(name);
        // The same message for an unknown user and a wrong password: no hint which one exists.
        return send(response, 401, html, loginPage(session.csrfToken, 'User name or password is wrong.'));
      }
      // A new session id after login, so an id planted before login is worthless (session fixation).
      store.endSession(sid);
      const fresh = store.createSession();
      fresh.session.userId = found.id;
      return send(response, 303, html, '', { location: '/notes', 'set-cookie': sessionCookie(fresh.id, has) });
    }

    if (route === 'POST /logout') {
      if (sid) store.endSession(sid);
      return send(response, 303, html, '', { location: '/', 'set-cookie': 'sid=; Path=/; Max-Age=0' });
    }

    if (route === 'GET /notes') {
      if (!user) return send(response, 303, html, '', { location: '/login' });
      return send(response, 200, html, notesPage(user.name, store.notesOf(user.id)));
    }

    if (url.pathname.startsWith('/api/')) {
      if (!user) return json(response, 401, { error: 'Sign in first' });
      if (route === 'GET /api/notes') return json(response, 200, store.notesOf(user.id));

      const match = /^\/api\/notes\/(\d+)$/.exec(url.pathname);
      const note = match ? store.notes.find((n) => n.id === Number(match[1])) : undefined;
      // Someone else's note answers 404, not 403: the API does not even confirm that the id exists.
      const visible = note && (note.ownerId === user.id || has('idor-read-other-notes')) ? note : undefined;
      if (match && request.method === 'GET') {
        return visible ? json(response, 200, visible) : json(response, 404, { error: 'Not found' });
      }
      if (match && request.method === 'PATCH') {
        const owned = note && note.ownerId === user.id ? note : undefined;
        if (!owned) return json(response, 404, { error: 'Not found' });
        // JSON only: a cross-site HTML form cannot send it, which blocks request forgery on this endpoint.
        if (!request.headers['content-type']?.startsWith('application/json')) {
          return json(response, 415, { error: 'Send application/json' });
        }
        let changes: Record<string, unknown>;
        try {
          changes = JSON.parse(await readBody(request)) as Record<string, unknown>;
        } catch {
          return json(response, 400, { error: 'Invalid JSON' });
        }
        const allowed = has('mass-assignment-owner') ? Object.keys(changes) : EDITABLE;
        for (const key of allowed) {
          if (key in changes && key !== 'id') (owned as unknown as Record<string, unknown>)[key] = changes[key];
        }
        return json(response, 200, owned);
      }
    }

    return send(response, 404, html, NOT_FOUND_PAGE);
  }
}

if (import.meta.main) {
  const { values } = parseArgs({
    options: {
      port: { type: 'string', default: '4320' },
      host: { type: 'string', default: '127.0.0.1' },
      build: { type: 'string', default: 'hardened' },
    },
  });
  if (values.build !== 'hardened' && values.build !== 'vulnerable') {
    throw new Error(`--build must be hardened or vulnerable, not ${values.build}`);
  }
  const build: Build = values.build;
  createApp(build).listen(Number(values.port), values.host, () => {
    console.log(`NoteVault (${build}) on http://${values.host}:${values.port}`);
  });
}
