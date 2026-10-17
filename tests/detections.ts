/**
 * For every planted defect: which tool must catch it and what it must report.
 *
 * ZAP sees what an outsider sees: response headers, cookies, and pages it can attack. It cannot know that note 3
 * belongs to bob, so access-control defects are caught by the API tests in tests/security.test.ts.
 */
import type { DefectId } from '../app/defects.ts';

export type Detection =
  | { tool: 'zap-baseline'; ruleId: string; rule: string }
  | { tool: 'zap-full'; ruleId: string; rule: string }
  | { tool: 'api-test'; finding: RegExp };

export const DETECTIONS: Record<DefectId, Detection> = {
  'no-csp': { tool: 'zap-baseline', ruleId: '10038', rule: 'Content Security Policy (CSP) Header Not Set' },
  'no-clickjacking-protection': { tool: 'zap-baseline', ruleId: '10020', rule: 'Missing Anti-clickjacking Header' },
  'no-nosniff': { tool: 'zap-baseline', ruleId: '10021', rule: 'X-Content-Type-Options Header Missing' },
  'cookie-not-httponly': { tool: 'zap-baseline', ruleId: '10010', rule: 'Cookie No HttpOnly Flag' },
  'cookie-no-samesite': { tool: 'zap-baseline', ruleId: '10054', rule: 'Cookie without SameSite Attribute' },
  'powered-by-header': { tool: 'zap-baseline', ruleId: '10037', rule: 'Server Leaks Information via "X-Powered-By"' },
  'reflected-xss': { tool: 'zap-full', ruleId: '40012', rule: 'Cross Site Scripting (Reflected)' },
  'idor-read-other-notes': { tool: 'api-test', finding: /^alice can read note 3 of bob/ },
  'mass-assignment-owner': { tool: 'api-test', finding: /^alice changed the owner of note 1/ },
  'no-login-rate-limit': { tool: 'api-test', finding: /^no limit: \d+ wrong passwords in a row were all answered 401/ },
};
