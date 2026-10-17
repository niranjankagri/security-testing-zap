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

function hashPassword(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, 32);
}

function makeUser(id: number, name: string): User {
  const salt = randomBytes(16);
  return { id, name, salt, hash: hashPassword(DEMO_PASSWORD, salt) };
}

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

  createSession(): { id: string; session: Session } {
    const id = randomBytes(24).toString('base64url');
    const session = { userId: null, csrfToken: randomBytes(24).toString('base64url') };
    this.sessions.set(id, session);
    return { id, session };
  }

  session(id: string | undefined): Session | undefined {
    return id ? this.sessions.get(id) : undefined;
  }

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

  notesOf(userId: number): Note[] {
    return this.notes.filter((n) => n.ownerId === userId);
  }
}
