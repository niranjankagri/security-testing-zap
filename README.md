# Security testing with OWASP ZAP

[![CI](https://github.com/niranjankagri/security-testing-zap/actions/workflows/ci.yml/badge.svg)](https://github.com/niranjankagri/security-testing-zap/actions/workflows/ci.yml)

Security checks a QA team can run on every change: **OWASP ZAP** baseline and full scans in Docker, with clear
pass/fail rules, plus **API tests** for the vulnerabilities a scanner cannot see.

The app under test is in the repository: **NoteVault**, a small notes app with sign-in, search and a JSON API (Node,
no dependencies). It comes in two builds of the same code: **hardened**, and **vulnerable** with ten planted defects.
The hardened build must scan clean; in the vulnerable build every defect must be reported by the tool named for it.
A scan that has only ever been clean has not shown that it can find anything.

**Why the app is in this repository:** a scan needs a target I am allowed to attack, that does not change by itself,
and whose problems are known. Each run starts fresh copies on a private Docker network; the vulnerable build is never
reachable from the host or the LAN, and is never deployed.

## Result

| Planted defect                                            | OWASP Top 10 (2021)                            | Caught by             |
| --------------------------------------------------------- | ---------------------------------------------- | --------------------- |
| `no-csp`: no Content-Security-Policy                      | A05 Security Misconfiguration                  | ZAP baseline [10038]  |
| `no-clickjacking-protection`: page can be framed          | A05 Security Misconfiguration                  | ZAP baseline [10020]  |
| `no-nosniff`: no X-Content-Type-Options                   | A05 Security Misconfiguration                  | ZAP baseline [10021]  |
| `cookie-not-httponly`: session cookie readable by scripts | A05 Security Misconfiguration                  | ZAP baseline [10010]  |
| `cookie-no-samesite`: session cookie sent cross-site      | A05 Security Misconfiguration                  | ZAP baseline [10054]  |
| `powered-by-header`: product and version advertised       | A05 Security Misconfiguration                  | ZAP baseline [10037]  |
| `reflected-xss`: search term not escaped                  | A03 Injection                                  | ZAP full scan [40012] |
| `idor-read-other-notes`: any note readable by id          | A01 Broken Access Control                      | API test              |
| `mass-assignment-owner`: `ownerId` accepted on update     | A01 Broken Access Control                      | API test              |
| `no-login-rate-limit`: unlimited password guesses         | A07 Identification and Authentication Failures | API test              |

ZAP caught all seven defects it can see, and none of the three access-control defects: it cannot know that note 3
belongs to bob. That is the point of the API tests next to it. The CI run page shows this table with live results
(`scripts/verify.ts` writes it into the job summary).

## What the scan found in the build I thought was done

- **Anti-CSRF Tokens Check:** after a failed token check, the error page showed the login form again with an empty
  token. It now links to a fresh form instead.
- **Bypassing 403:** `/%2e/login` was served as `/login`. Nothing could be bypassed (no path-based access rules), but
  accepting ambiguous paths is how such bypasses start. Non-canonical paths now get 400. The rescan still reported
  the rule, now for `/login?`: the failed token check answered 403, so ZAP took `/login` for a protected path and the
  public login page for a bypass. A false positive; the token check now answers 400 (the request is invalid, not
  forbidden), and the rule stays FAIL for real bypasses.

## How it works

```
npm run scan:full
  ├─ docker network "notevault-scan" (no ports published)
  ├─ notevault-hardened   (node:24.22.0-alpine, repository mounted read-only)
  ├─ notevault-vulnerable (same image, --build vulnerable)
  └─ ghcr.io/zaproxy/zaproxy:2.17.0
       zap-baseline.py  spider + passive rules  ─┐
       zap-full-scan.py + active attacks        ─┴─► reports/zap/<build>-<scan>.json + .html
npm run verify
  hardened:   only IGNORE alerts (and informational WARNs) allowed
  vulnerable: every defect ZAP is responsible for must appear as its rule id
npm test
  API tests: IDOR, mass assignment, brute force, CSRF on login, session fixation, user enumeration, ...
```

- [`zap/rules.tsv`](zap/rules.tsv): every rule of both scans with FAIL, WARN or IGNORE. FAIL for the rules behind the
  planted defects and for classic high-impact problems (XSS, SQL and command injection, path traversal); IGNORE only
  with a reason.
- [`app/defects.ts`](app/defects.ts): the catalogue. The server asks `has('<id>')` exactly where each defect is
  planted; a unit test fails if one disappears.
- [`tests/detections.ts`](tests/detections.ts): which tool must catch each defect and what it must report.

## Running it (Windows cmd)

Needs Node 24.2 or later and Docker Desktop.

```
cd /d D:\Data\Work\security-testing-zap
npm ci

npm test                 API security tests and unit tests (seconds, no Docker)
npm run scan             ZAP baseline scan of both builds
npm run scan:full        baseline and full scan of both builds (about 9 minutes)
npm run verify           judge the reports; add -- --full to require the full scans
npm run app              the hardened build on http://127.0.0.1:4320 (demo users alice and bob)
```

The HTML reports are in `reports\zap`.

## Project structure

```
app/
  server.ts            routes, security headers, session cookie, sign-in, API; has('<defect>') switches
  store.ts             users (scrypt hashes), notes, sessions, failed-login counter
  pages.ts             HTML pages; escapeHtml on every value
  defects.ts           the ten planted defects with OWASP category and impact
zap/rules.tsv          ZAP rule actions for both scans
scripts/
  scan.ts              private network, both builds, ZAP baseline/full, clean-up
  zap-results.ts       parse reports and rules, decide what is not allowed
  verify.ts            the verdict and the Markdown summary
tests/
  checks.ts            IDOR, mass assignment and brute-force checks (return findings)
  client.ts            signs in through the real form, keeps the session cookie
  security.test.ts     each check on both builds, plus CSRF, fixation, enumeration, JSON-only, paths, escaping
  unit.test.ts         report parsing, rules, catalogue completeness
  detections.ts        defect → tool → expected finding
```

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml): typecheck, lint, format and the API tests; then one job per
build running the baseline and the full scan in parallel; then a job that downloads both reports, judges them and
writes the summary table. The ZAP reports are kept as artifacts for 14 days.

## Limits

- The scans are unauthenticated: signed-in pages are covered by the API tests, not by ZAP. A ZAP context with a login
  would add them.
- HTTP inside a private network: HSTS and TLS settings need a scan of a deployed environment.
- DAST is one layer. Dependency scanning, static analysis and a penetration test before major releases are not
  replaced by it. See [docs/framework-design.md](docs/framework-design.md) and
  [docs/interview-questions.md](docs/interview-questions.md).

## License

MIT
