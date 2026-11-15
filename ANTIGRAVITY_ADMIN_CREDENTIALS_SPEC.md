# Antigravity MCP: owner-only admin page (GitHub credentials + allowed repositories)

Implement this spec exactly. Edit only `src/index.ts`, `test/index.spec.ts` and `README.md`. Do not touch `.github/`, `wrangler.jsonc`, `package.json`, `package-lock.json`. No new dependencies, bindings or required environment variables. Reuse the existing owner-passphrase verification, the existing single-use CSRF nonce mechanism and the existing Durable Object attempt throttle. Do not duplicate or weaken them.

## 1. Why

Repo modes (`inspect`, `review`, `propose`, `implement`) need Google-side credentials that hold a GitHub token. Google stores a credential once (`POST https://generativelanguage.googleapis.com/v1beta/credentials`, JSON body `{ "id": "<id>", "type": "bearer_token", "token": "<github token>" }`, header `x-goog-api-key`) and the agent references it by id only. The owner has no terminal and the token must never pass through chat. This page lets the owner store the token at Google directly from the browser, and manage which repositories the agent may target.

## 2. Page and routes

- `GET /admin/credentials` and `POST /admin/credentials`. Any other method returns 405. Not linked from anywhere.
- Available only when owner-passphrase mode is configured (same condition the consent page uses). Otherwise both methods return a generic 404 and the page does not exist.
- Stateless: no cookie, no session. Every POST requires the owner passphrase typed in the form.
- Responses always set: `Cache-Control: no-store`, `Content-Type: text/html; charset=utf-8`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and a CSP of `default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`. Escape every dynamic value written into HTML.
- POST never redirects: it renders the result page directly (this avoids the earlier Chromium `form-action` problem with redirects).
- Request body limit 8 KB (reject larger with 413). Reject missing or unexpected content types with 415.

## 3. Page content

Status block (no secrets, ever): for each slot `read` and `write`: "configured" or "not configured" with the saved date (ISO date only). The allowed repositories list. Then these forms (each has the CSRF nonce and a passphrase field, `autocomplete="off"`, token field `type="password"`):
1. Save credential: select slot (`read` or `write`), GitHub token field, checkbox "replace if exists". 
2. Delete credential: select slot.
3. Set allowed repositories: textarea, one `owner/repo` per line.

## 4. POST handling order (fail closed, same shape as the consent page)
1. Method, content type, size checks.
2. Record the attempt in the existing throttle BEFORE verifying anything (shared budget with the consent page; HTTP 429 when exhausted; fail closed if the throttle store errors).
3. Verify and consume the single-use CSRF nonce.
4. Constant-time passphrase comparison exactly as the consent page does it. On failure return one generic message ("Invalid request") with HTTP 400, identical for wrong passphrase, bad nonce and malformed input.
5. Dispatch the action (below).
6. A successful passphrase resets the throttle exactly as the consent page does.

## 5. Actions

Fixed credential ids (the slot decides the id, never user input): `read` -> `antigravity-github-read`, `write` -> `antigravity-github-write`.

**Save credential**
- Token validation: trimmed, 20 to 255 characters, no whitespace or control characters, must start with `github_pat_` or `ghp_`. Reject anything else with a generic message that does not echo the input.
- Call Google `POST /v1beta/credentials` with a 15 s timeout (`AbortSignal.timeout`), `x-goog-api-key` header from `GEMINI_API_KEY`.
- If Google reports the id already exists (HTTP 409 or an `ALREADY_EXISTS` status) and "replace if exists" is ticked: `DELETE /v1beta/credentials/<id>` then create again once. Without the tick, show "already exists, tick replace".
- On success record `antigravity:config:credential:<slot>` in `OAUTH_KV` as `{ "id": "<fixed id>", "savedAt": "<ISO>" }` (no token, no token fragment, no hash).
- Any Google error: show a short generic message plus the HTTP status code only. Never show Google's body. Run every message through `sanitizeSecret` for both the API key and the submitted token.
- The submitted token must never be logged, stored, echoed, placed in an error, or kept after the request ends.

**Delete credential**: `DELETE /v1beta/credentials/<fixed id>` (a not-found answer counts as success), then delete the KV record.

**Set allowed repositories**: parse lines, trim, drop blanks; each must match `^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`; at most 50 entries; lowercase on save; deduplicate. Store as JSON array in `antigravity:config:allowed-repositories`. An empty list is valid and means no repository is allowed.

Log one line per action with `console.log`: `admin_credentials action=<save|delete|repos> slot=<slot or ->  result=<ok|rejected|error> status=<http status or ->` and nothing else (no token, no passphrase, no user input).

## 6. How the rest of the server uses this config

- Credential id resolution for repo modes: use the existing environment variable if it is set (`GITHUB_MCP_READ_CREDENTIAL_ID`, `GITHUB_MCP_WRITE_CREDENTIAL_ID`), otherwise the id from the KV record for that slot, otherwise fail closed with the existing "not configured" error. Modes `inspect`, `review`, `propose` use the read slot; `implement` uses the write slot (keep the current mode-to-credential mapping).
- Repository allowlist: every call that has a `repository` (any mode) must match the allowlist (case-insensitive, exact `owner/repo`). Source: the environment variable `ALLOWED_REPOSITORIES` (comma-separated) if set, otherwise the KV list. An empty or missing list denies every repository (fail closed) with a clear error naming the admin page path. This check runs before any Google call and before any credential lookup.
- KV read failures in this resolution fail closed (deny), never open.
- Keep the `implement` system instruction, draft-PR behavior and all other behavior unchanged.

## 7. Also in this change: `includeSteps` keeps the last steps
In `compactInteractionSteps`, when there are more than 100 non-thought steps keep the LAST 100 (not the first 100) and add `omittedSteps` (count of older steps dropped) to the result when greater than zero.

## 8. Tests (`test/index.spec.ts`)
Mock `fetch` and use the existing test helpers for passphrase mode. Cover at least:
1. Both methods return 404 when passphrase mode is not configured; other methods return 405.
2. GET renders status and forms with a CSRF nonce, never any token; response headers as in section 2.
3. POST with a wrong passphrase, a bad or reused nonce, and malformed input all return the same generic 400; throttle is recorded before verification; 429 after the limit; throttle failure fails closed.
4. Save: correct Google request (URL, header, JSON body, fixed id per slot); success writes only `{id, savedAt}` to KV; the token appears in no response, KV value, console output or error path (assert with a distinctive token).
5. Save: invalid token shapes rejected without calling Google; Google 4xx and 5xx give a generic message with status only; timeout handled; exists without the tick shows the hint; exists with the tick deletes then creates.
6. Delete: calls Google DELETE with the fixed id; not-found counts as success; KV record removed.
7. Allowed repositories: parsing, validation, limit of 50, lowercase, dedupe, empty list allowed.
8. Server behavior: env var beats KV for credential ids; with KV only the id is used; neither fails closed; repository not on the allowlist is rejected before any Google or KV credential call; empty allowlist denies everything; KV errors deny.
9. `includeSteps` keeps the last 100 steps and reports `omittedSteps`.
10. Existing consent, passphrase, throttle and CSRF tests still pass unchanged.

## 9. Acceptance
Type-check and the full test suite pass; report real output. No edits outside the three files. The final message lists every file touched and every existing test changed (there should be none besides what section 6 forces; explain each).
