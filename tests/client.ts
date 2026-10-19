/**
 * A minimal browser-like HTTP client for the API tests: keeps the session cookie and signs in through the real
 * login form (with its anti-CSRF token), so the tests use the app the way a user does.
 */
export class Client {
  private sid = '';
  private readonly base: string;

  // A plain field, not a "parameter property": Node's type stripping only removes types, it cannot rewrite code.
  constructor(base: string) {
    this.base = base;
  }

  /**
   * One request with the session cookie; a Set-Cookie in the answer replaces it. Redirects are not followed, so tests
   * can check the 303 itself.
   */
  async request(path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (this.sid) headers.set('cookie', `sid=${this.sid}`);
    const response = await fetch(this.base + path, { ...init, headers, redirect: 'manual' });
    const cookie = /^sid=([^;]*)/.exec(response.headers.get('set-cookie') ?? '');
    if (cookie) this.sid = cookie[1] ?? '';
    return response;
  }

  /** Opens the login page and returns the form's anti-CSRF token. */
  async loginForm(): Promise<string> {
    const page = await (await this.request('/login')).text();
    const token = /name="csrf_token" value="([^"]+)"/.exec(page)?.[1];
    if (!token) throw new Error('no csrf_token in the login form');
    return token;
  }

  /** Submits the login form; returns the status (303 = signed in). */
  async login(name: string, password: string, token?: string): Promise<number> {
    const csrf = token ?? (await this.loginForm());
    const body = new URLSearchParams({ csrf_token: csrf, name, password });
    const response = await this.request('/login', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    await response.arrayBuffer();
    return response.status;
  }

  /** The current session id, for tests about the cookie. */
  get sessionId(): string {
    return this.sid;
  }

  /** A request whose answer is JSON (or empty): the status and the parsed body. */
  async json(path: string, init: RequestInit = {}): Promise<{ status: number; body: unknown }> {
    const response = await this.request(path, init);
    const text = await response.text();
    return { status: response.status, body: text ? (JSON.parse(text) as unknown) : null };
  }
}
