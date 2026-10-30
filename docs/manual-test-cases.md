# Manual test cases

The security test cases this project automates on NoteVault, written as a tester would run them by
hand with a browser, curl and OWASP ZAP. Every case has an ID; the test that covers it starts with the
same ID (`[TC-206] rejects a login without the form token ...`), and the ZAP case is the heading of
its section in the scan results (`### [TC-213] Hardened build: ...`), so a failure leads straight to
the case below.

| ID range         | Area                                                | Automated in                                 |
| ---------------- | --------------------------------------------------- | -------------------------------------------- |
| TC-201 to TC-203 | Access control and abuse checks a scanner cannot do | `tests/security.test.ts` (`tests/checks.ts`) |
| TC-204 to TC-212 | Security behaviour users rely on                    | `tests/security.test.ts`                     |
| TC-213           | OWASP ZAP scan: only accepted alerts                | `scripts/scan.ts` + `scripts/verify.ts` (CI) |

All cases run against the **hardened** build. The same checks against the deliberately **vulnerable**
build (each planted defect must be found) test the tests, so they have no ID; neither do the unit
tests (`tests/unit.test.ts`).

## Setup

- `npm ci`, then `node app/server.ts --port 4320` (hardened build); open <http://localhost:4320>.
- Users: `alice` (notes 1 and 2) and `bob` (note 3), password `NoteVault-demo-1`.
- The login form carries a hidden `csrf_token`; API calls use the session cookie from the login.
- Login limit: 5 wrong passwords in a row for one user.
- For TC-213: Docker (ZAP runs in a container), `npm run scan`, then `npm run verify`. Rule actions in
  `zap/rules.tsv` (FAIL: must never appear; IGNORE: accepted with a reason; WARN: reviewed).

## Summary

| ID     | Title                                                            | OWASP category              | Priority |
| ------ | ---------------------------------------------------------------- | --------------------------- | -------- |
| TC-201 | A user cannot read another user's note by changing the id (IDOR) | A01 Broken access control   | High     |
| TC-202 | A user cannot change a note's owner (mass assignment)            | A01 / API6                  | High     |
| TC-203 | Wrong passwords are limited after 5 attempts (brute force)       | A07 Authentication failures | High     |
| TC-204 | Alice signs in and sees only her own notes                       | A01                         | High     |
| TC-205 | The API answers 401 before sign-in                               | A01 / A07                   | High     |
| TC-206 | A login without the form token is rejected (CSRF)                | A01 CSRF                    | High     |
| TC-207 | The expired-token page shows no form                             | CSRF                        | Low      |
| TC-208 | Sign-in issues a new session id (session fixation)               | A07                         | High     |
| TC-209 | Unknown user and wrong password get the same answer              | A07 (user enumeration)      | Medium   |
| TC-210 | The update endpoint accepts only JSON                            | A05 Misconfiguration        | Medium   |
| TC-211 | Ambiguous paths are refused, not normalised                      | A01 (path traversal)        | Medium   |
| TC-212 | The search term is escaped (XSS)                                 | A03 Injection               | High     |
| TC-213 | ZAP scan of the hardened build: only accepted alerts             | All (scanner)               | High     |

---

### TC-201 A user cannot read another user's note by changing the id (IDOR)

| #   | Step                                                 | Expected result                         |
| --- | ---------------------------------------------------- | --------------------------------------- |
| 1   | Sign in as alice                                     | Redirect (`303`) to her notes           |
| 2   | `GET /api/notes/3` (bob's note) with alice's session | **Not** `200` (no access to bob's note) |

### TC-202 A user cannot change a note's owner (mass assignment)

| #   | Step                                                                             | Expected result                                                                  |
| --- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| 1   | As alice `PATCH /api/notes/1`, JSON `{"title":"Groceries (edited)","ownerId":2}` | `200`; the title changes                                                         |
| 2   | Read the answer (or the note)                                                    | `ownerId` is still alice's (`1`), not `2`: `ownerId` from the request is ignored |

### TC-203 Wrong passwords are limited after 5 attempts (brute force)

| #   | Step                                                            | Expected result                                                  |
| --- | --------------------------------------------------------------- | ---------------------------------------------------------------- |
| 1   | Open the login form; submit `bob` with a wrong password 5 times | `401` each time                                                  |
| 2   | Submit a 6th wrong password                                     | `429 Too Many Requests` (exactly at the attempt after the limit) |

### TC-204 Alice signs in and sees only her own notes

| #   | Step                               | Expected result                      |
| --- | ---------------------------------- | ------------------------------------ |
| 1   | Sign in as alice, `GET /api/notes` | `200`; two notes, both `ownerId` `1` |

### TC-205 The API answers 401 before sign-in

| #   | Step                               | Expected result |
| --- | ---------------------------------- | --------------- |
| 1   | Without a session `GET /api/notes` | `401`           |

### TC-206 A login without the form token is rejected (CSRF)

| #   | Step                                                                                                                | Expected result      |
| --- | ------------------------------------------------------------------------------------------------------------------- | -------------------- |
| 1   | Open the login form (gets a session and a token); submit alice's correct credentials with `csrf_token=forged-token` | `400`; not signed in |

### TC-207 The expired-token page shows no form

| #   | Step                                                                         | Expected result                                                                             |
| --- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| 1   | Submit the login with a forged token (as TC-206) and look at the answer page | `400`; **no** `<form>` on the page (it could never carry a valid token); a link to `/login` |

### TC-208 Sign-in issues a new session id (session fixation)

| #   | Step                                         | Expected result                               |
| --- | -------------------------------------------- | --------------------------------------------- |
| 1   | Open the login form, note the session cookie | e.g. `sid=abc...`                             |
| 2   | Sign in as alice                             | `303`; the session cookie has a **new** value |

### TC-209 Unknown user and wrong password get the same answer

| #   | Step                                                              | Expected result                                                                    |
| --- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| 1   | Sign in as `alice` with password `wrong`; note status and message |                                                                                    |
| 2   | Sign in as `mallory` (no such user) with `wrong`                  | Same status and the same message: the answer does not reveal which usernames exist |

### TC-210 The update endpoint accepts only JSON

| #   | Step                                                         | Expected result              |
| --- | ------------------------------------------------------------ | ---------------------------- |
| 1   | As alice `PATCH /api/notes/1` with body `title=x` (not JSON) | `415 Unsupported Media Type` |

### TC-211 Ambiguous paths are refused, not normalised

Send the raw path (curl `--path-as-is`; a browser would normalise it).

| Data set | Path              | Expected |
| -------- | ----------------- | -------- |
| 1        | `/%2e/login`      | `400`    |
| 2        | `//login`         | `400`    |
| 3        | `/notes/../login` | `400`    |

### TC-212 The search term is escaped (XSS)

| #   | Step                                       | Expected result                                                                                                |
| --- | ------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| 1   | Open `/search?q=<script>alert(1)</script>` | No alert box; the page shows "Results for &lt;script&gt;alert(1)&lt;/script&gt;" as text (escaped in the HTML) |

### TC-213 ZAP scan of the hardened build: only accepted alerts

| #   | Step                                                                                                                  | Expected result                                                                                                                                                   |
| --- | --------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `npm run scan` (ZAP baseline scan; `npm run scan:full` adds the active scan)                                          | Reports in `reports/`                                                                                                                                             |
| 2   | `npm run verify`                                                                                                      | Section "[TC-213] Hardened build": no alert with action FAIL, and no WARN alert above Informational; only IGNORE alerts (each with its reason in `zap/rules.tsv`) |
| 3   | By hand in the ZAP desktop app: spider `http://localhost:4320`, passive scan, compare the alerts with `zap/rules.tsv` | Same result                                                                                                                                                       |
