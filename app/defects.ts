/**
 * The vulnerabilities that the "vulnerable" build of NoteVault has on purpose.
 *
 * The code asks `has('<id>')` exactly where each one is planted, so a search for the id finds it. The suite proves it
 * works by catching every one of them: tests/detections.ts names the tool and the finding for each id.
 * NEVER deploy the vulnerable build anywhere; the scan scripts run it on a private Docker network only.
 */
export type DefectId =
  | 'no-csp'
  | 'no-clickjacking-protection'
  | 'no-nosniff'
  | 'cookie-not-httponly'
  | 'cookie-no-samesite'
  | 'powered-by-header'
  | 'reflected-xss'
  | 'idor-read-other-notes'
  | 'mass-assignment-owner'
  | 'no-login-rate-limit';

export interface Defect {
  id: DefectId;
  /** What a team might have changed or forgotten, and what an attacker gets. */
  story: string;
  /** OWASP Top 10 (2021) category. */
  owasp: string;
}

export const DEFECTS: readonly Defect[] = [
  {
    id: 'no-csp',
    story: 'No Content-Security-Policy: any injected script runs with the full power of the page.',
    owasp: 'A05 Security Misconfiguration',
  },
  {
    id: 'no-clickjacking-protection',
    story: 'Pages may be framed by any site, which can trick users into clicking hidden buttons (clickjacking).',
    owasp: 'A05 Security Misconfiguration',
  },
  {
    id: 'no-nosniff',
    story: 'No X-Content-Type-Options: browsers may guess content types and run an uploaded text file as script.',
    owasp: 'A05 Security Misconfiguration',
  },
  {
    id: 'cookie-not-httponly',
    story: 'The session cookie is readable from JavaScript, so one XSS bug is enough to steal sessions.',
    owasp: 'A05 Security Misconfiguration',
  },
  {
    id: 'cookie-no-samesite',
    story: 'The session cookie is sent with requests from other sites, which makes cross-site request forgery easier.',
    owasp: 'A05 Security Misconfiguration',
  },
  {
    id: 'powered-by-header',
    story: 'An X-Powered-By header names the product and version, telling attackers which exploits to try.',
    owasp: 'A05 Security Misconfiguration',
  },
  {
    id: 'reflected-xss',
    story: 'The search term is written into the page without escaping: a link can run script in the victim’s session.',
    owasp: 'A03 Injection',
  },
  {
    id: 'idor-read-other-notes',
    story: 'The API returns any note by id without checking its owner: change the number in the URL, read other notes.',
    owasp: 'A01 Broken Access Control',
  },
  {
    id: 'mass-assignment-owner',
    story:
      'The update endpoint copies every field it receives, including ownerId: notes can be moved between accounts.',
    owasp: 'A01 Broken Access Control',
  },
  {
    id: 'no-login-rate-limit',
    story: 'Unlimited login attempts: passwords can be guessed by brute force.',
    owasp: 'A07 Identification and Authentication Failures',
  },
];

export type Build = 'hardened' | 'vulnerable';

/** The defects a build contains: none for "hardened", all for "vulnerable". */
export function defectsOf(build: Build): ReadonlySet<DefectId> {
  return new Set(build === 'vulnerable' ? DEFECTS.map((d) => d.id) : []);
}
