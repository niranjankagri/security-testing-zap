/**
 * In-memory data: users, notes, sessions and the login attempt counter. Restarting the server resets everything.
 */
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

export interface User {
  id: number;
  name: string;
  salt: Buffer;
  hash: Buffer;
}

export interface Note {
  id: number;
  ownerId: number;
  title: string;
  text: string;
}

export interface Session {
  userId: number | null;
  /** Anti-CSRF token for the login form, bound to this session. */
  csrfToken: string;
}

/** Demo password of both users. Public on purpose: this app only ever runs locally or in CI. */
export const DEMO_PASSWORD = 'NoteVault-demo-1';

/** At most this many failed logins per user name in the window; then 429 until the window has passed. */
export const LOGIN_LIMIT = 5;
export const LOGIN_WINDOW_MS = 15 * 60 * 1000;

/** scrypt with a per-user salt: slow on purpose, so a stolen hash is expensive to crack. */
function hashPassword(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, 32);
}

/** A demo user with the demo password, hashed with a fresh salt. */
function makeUser(id: number, name: string): User {
  const salt = randomBytes(16);
  return { id, name, salt, hash: hashPassword(DEMO_PASSWORD, salt) };
}

/** In-memory data of one app instance: the two demo users, their notes, the sessions and the failed-login counts. */
export class Store {
  readonly users: User[] = [makeUser(1, 'alice'), makeUser(2, 'bob')];
  readonly notes: Note[] = [
    { id: 1, ownerId: 1, title: 'Groceries', text: 'Oat milk, apples, coffee' },
    { id: 2, ownerId: 1, title: 'Holiday', text: 'Book the ferry before May' },
    { id: 3, ownerId: 2, title: 'Bank PIN reminder', text: 'Ask the bank to send a new PIN letter' },
  ];
  private readonly sessions = new Map<string, Session>();
  private readonly failedLogins = new Map<string, number[]>();

  /** Checks a password in constant time, so response times do not reveal how much of it was right. */
  authenticate(name: string, password: string): User | undefined {
    const user = this.users.find((u) => u.name === name);
    if (!user) return undefined;
    return timingSafeEqual(hashPassword(password, user.salt), user.hash) ? user : undefined;
  }

  /**
   * A new anonymous session with random id and anti-CSRF token (24 random bytes each); signing in fills in the user.
   */
  createSession(): { id: string; session: Session } {
    const id = randomBytes(24).toString('base64url');
    const session = { userId: null, csrfToken: randomBytes(24).toString('base64url') };
    this.sessions.set(id, session);
    return { id, session };
  }

  /** The session with this id, or undefined. */
  session(id: string | undefined): Session | undefined {
    return id ? this.sessions.get(id) : undefined;
  }

  /** Ends a session (sign-out); the old cookie is worthless afterwards. */
  endSession(id: string): void {
    this.sessions.delete(id);
  }

  /** Records a failed login for this user name (old attempts outside the window are dropped). */
  recordFailedLogin(name: string, now = Date.now()): void {
    const recent = (this.failedLogins.get(name) ?? []).filter((t) => now - t < LOGIN_WINDOW_MS);
    recent.push(now);
    this.failedLogins.set(name, recent);
  }

  isLocked(name: string, now = Date.now()): boolean {
    const recent = (this.failedLogins.get(name) ?? []).filter((t) => now - t < LOGIN_WINDOW_MS);
    return recent.length >= LOGIN_LIMIT;
  }

  /** The notes that belong to this user. */
  notesOf(userId: number): Note[] {
    return this.notes.filter((n) => n.ownerId === userId);
  }
}
