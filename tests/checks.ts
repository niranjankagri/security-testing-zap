/**
 * Security checks a scanner cannot do, because they need to know who owns what. Each returns findings
 * (empty = fine), so the same check proves the hardened build clean and the vulnerable build caught.
 */
import { DEMO_PASSWORD, LOGIN_LIMIT } from '../app/store.ts';
import { Client } from './client.ts';

/** Broken object level authorization (IDOR): can alice read bob's note by changing the id? */
export async function idorFindings(base: string): Promise<string[]> {
  const alice = new Client(base);
  if ((await alice.login('alice', DEMO_PASSWORD)) !== 303) return ['alice could not sign in'];
  const { status, body } = await alice.json('/api/notes/3');
  return status === 200 ? [`alice can read note 3 of bob: ${JSON.stringify(body)}`] : [];
}

/** Mass assignment: can alice change a field she must not, here the owner of her note? */
export async function massAssignmentFindings(base: string): Promise<string[]> {
  const alice = new Client(base);
  if ((await alice.login('alice', DEMO_PASSWORD)) !== 303) return ['alice could not sign in'];
  const patch = await alice.json('/api/notes/1', {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ title: 'Groceries (edited)', ownerId: 2 }),
  });
  if (patch.status !== 200) return [`the allowed part of the change failed with ${patch.status}`];
  const owner = (patch.body as { ownerId?: number }).ownerId;
  return owner === 2 ? ['alice changed the owner of note 1 to bob (ownerId was accepted from the request)'] : [];
}

/** Brute force: are wrong passwords for one user limited? */
export async function rateLimitFindings(base: string): Promise<string[]> {
  const attacker = new Client(base);
  const token = await attacker.loginForm();
  const attempts = LOGIN_LIMIT + 2;
  const statuses: number[] = [];
  for (let i = 0; i < attempts; i++) statuses.push(await attacker.login('bob', `guess-${i}`, token));
  if (!statuses.includes(429)) return [`no limit: ${attempts} wrong passwords in a row were all answered 401`];
  // Limited, but also at the right moment: the attempt after the limit, not later.
  return statuses[LOGIN_LIMIT] === 429 ? [] : [`limit came late: ${statuses.join(', ')}`];
}
