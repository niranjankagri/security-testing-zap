// API security tests (node:test, no browser, no Docker): npm test
// Each check runs against a fresh hardened build (no findings allowed) and a fresh vulnerable build (its planted
// defect must be reported).
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { after, describe, it } from 'node:test';
import { DEMO_PASSWORD } from '../app/store.ts';
import { createApp } from '../app/server.ts';
import type { Build } from '../app/defects.ts';
import { idorFindings, massAssignmentFindings, rateLimitFindings } from './checks.ts';
import { Client } from './client.ts';
import { DETECTIONS } from './detections.ts';

const servers: { close: () => void }[] = [];
after(() => servers.forEach((s) => s.close()));

/** Starts a fresh app on a free port and returns its base URL. */
async function start(build: Build): Promise<string> {
  const server = createApp(build);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  servers.push(server);
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

const CHECKS = [
  { defect: 'idor-read-other-notes', check: idorFindings },
  { defect: 'mass-assignment-owner', check: massAssignmentFindings },
  { defect: 'no-login-rate-limit', check: rateLimitFindings },
] as const;

for (const { defect, check } of CHECKS) {
  describe(check.name, () => {
    it('finds nothing in the hardened build', async () => {
      assert.deepEqual(await check(await start('hardened')), []);
    });

    it(`reports the planted ${defect} in the vulnerable build`, async () => {
      const detection = DETECTIONS[defect];
      assert.equal(detection.tool, 'api-test');
      const findings = await check(await start('vulnerable'));
      assert.ok(
        detection.tool === 'api-test' && findings.some((f) => detection.finding.test(f)),
        `expected a finding matching ${String(detection.tool === 'api-test' && detection.finding)}, got ${JSON.stringify(findings)}`,
      );
    });
  });
}

describe('hardened build: the security behaviour users rely on', () => {
  it('lets alice sign in and see only her own notes', async () => {
    const alice = new Client(await start('hardened'));
    assert.equal(await alice.login('alice', DEMO_PASSWORD), 303);
    const { status, body } = await alice.json('/api/notes');
    assert.equal(status, 200);
    assert.deepEqual(
      (body as { ownerId: number }[]).map((n) => n.ownerId),
      [1, 1],
    );
  });

  it('answers the API with 401 before sign-in', async () => {
    const anonymous = new Client(await start('hardened'));
    assert.equal((await anonymous.json('/api/notes')).status, 401);
  });

  it('rejects a login without the form token (cross-site request forgery)', async () => {
    const client = new Client(await start('hardened'));
    await client.loginForm();
    assert.equal(await client.login('alice', DEMO_PASSWORD, 'forged-token'), 403);
  });

  it('issues a new session id at sign-in (session fixation)', async () => {
    const client = new Client(await start('hardened'));
    await client.loginForm();
    const before = client.sessionId;
    assert.equal(await client.login('alice', DEMO_PASSWORD), 303);
    assert.notEqual(client.sessionId, before);
  });

  it('gives the same answer for an unknown user and a wrong password', async () => {
    const base = await start('hardened');
    const pages = [];
    for (const name of ['alice', 'mallory']) {
      const client = new Client(base);
      const token = await client.loginForm();
      const response = await client.request('/login', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ csrf_token: token, name, password: 'wrong' }),
      });
      pages.push([response.status, /role="alert">([^<]*)/.exec(await response.text())?.[1]]);
    }
    assert.deepEqual(pages[0], pages[1]);
  });

  it('accepts only JSON on the update endpoint', async () => {
    const alice = new Client(await start('hardened'));
    await alice.login('alice', DEMO_PASSWORD);
    const response = await alice.request('/api/notes/1', { method: 'PATCH', body: 'title=x' });
    assert.equal(response.status, 415);
  });

  it('refuses ambiguous paths instead of normalising them', async () => {
    const base = await start('hardened');
    for (const path of ['/%2e/login', '//login', '/notes/../login']) {
      // fetch would normalise "/notes/../login" itself, so the raw request goes through node:http.
      const status = await rawStatus(base, path);
      assert.equal(status, 400, path);
    }
  });

  it('escapes the search term', async () => {
    const page = await (await fetch(`${await start('hardened')}/search?q=<script>alert(1)</script>`)).text();
    assert.match(page, /Results for &lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  });
});

/** Sends a request with the path exactly as given (no client-side normalisation). */
async function rawStatus(base: string, path: string): Promise<number> {
  const { request } = await import('node:http');
  const url = new URL(base);
  return new Promise((resolve, reject) => {
    request({ host: url.hostname, port: url.port, path, method: 'GET' }, (response) => {
      response.resume();
      resolve(response.statusCode ?? 0);
    })
      .on('error', reject)
      .end();
  });
}
