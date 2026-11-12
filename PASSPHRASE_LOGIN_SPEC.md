# Owner passphrase login for /oauth/authorize

## Why
Cloudflare Access is not available (no Zero Trust account). The only working login today is Access (or signed HMAC headers that no browser can send), so /oauth/authorize rejects everyone. Add a third, fail-closed mechanism: a single-owner passphrase typed on the consent page.

## Scope
Only `src/index.ts` (authorization code path), `test/index.spec.ts`, `README.md`. Do NOT edit: `.github/`, `wrangler.jsonc`, `package.json`, `package-lock.json`, MCP tool code, bearer-token validation, Access JWT code, HMAC code. Do not remove or weaken existing behavior or existing tests.

## Config
- New optional secret `OWNER_PASSPHRASE` (add to `Env`).
- Passphrase mode is "configured" only if: `OWNER_PASSPHRASE` trimmed length >= 24, AND the first entry of `ALLOWED_USERS` (trimmed, lowercased) is non-empty and is not `*`. Otherwise treat as not configured (fail closed).
- Owner id = that first `ALLOWED_USERS` entry.

## Mode selection in the `/oauth/authorize` handler
1. If the request has `Cf-Access-Jwt-Assertion` OR `env.AUTH_SECRET` is set: behavior is exactly as today.
2. Else if passphrase mode is configured: passphrase mode (below).
3. Else: the existing 403 response, unchanged.

## Passphrase mode
- Never auto-approve through `TRUSTED_CLIENT_IDS` in this mode.
- Keep every existing check (PKCE S256 required, scope, resource, client lookup) before anything else.
- Non-POST: render the existing consent page for the owner id, with one extra field: `<input type="password" name="owner_passphrase" autocomplete="current-password" required>` and a visible label. CSRF token is created as today, bound to the owner id. The consent page keeps its current CSP and headers.
- POST, in this order:
  1. Throttle check (see below). If locked: HTTP 429, JSON `{error:"access_denied", error_description:"Too many failed attempts. Try again later."}`.
  2. Verify and consume the CSRF token exactly as today (owner id as the user id).
  3. If `consent_action` is `deny`: redirect with access_denied as today (no passphrase needed).
  4. If `approve`: compare SHA-256 digests of the submitted and configured passphrase in constant time (`crypto.subtle.timingSafeEqual` or the constant-time helper already in the repo). Missing field counts as wrong.
     - Wrong: record a failure, return 403 JSON `{error:"access_denied", error_description:"Incorrect passphrase."}`.
     - Right: reset the failure counter, then `completeAuthorization` with the owner id and the requested scopes, redirect as today.

## Throttle
- 5 failed passphrase attempts within a 15-minute window lock further POST attempts until the window expires. Success resets the counter.
- Global counter (single owner), stored in the existing `ConsentCoordinatorDO` using a dedicated fixed shard name; add methods to that class. Do not change `wrangler.jsonc` or migrations.

## Secret hygiene
- The passphrase must never appear in any response body, HTML, redirect URL, error text, log line or thrown error. It is only ever read from a POST form body.
- Use `escapeHtml` for every value rendered in HTML, as the current page does.

## Tests (vitest, existing style in `test/index.spec.ts`)
Add tests for: not configured (missing, shorter than 24 chars, `ALLOWED_USERS` of `*` or empty) => existing 403; configured GET shows the passphrase field and no auth needed; wrong passphrase => 403 and no authorization code; missing passphrase => 403; right passphrase => redirect carrying a code; trusted client id is NOT auto-approved in this mode; deny works without a passphrase; 5 failures lock and the 6th attempt with the RIGHT passphrase returns 429; success resets the counter; CSRF token reuse is rejected; the passphrase never appears in any response or error; Access/HMAC paths still behave as before (existing tests must pass untouched).

## README
Document `OWNER_PASSPHRASE` (secret, generate 40+ random characters, set only in the Cloudflare dashboard as a secret) and that Access is optional, not required.

## Done means
`npm test` and `npx tsc --noEmit` pass; the final message lists every changed file with one sentence each and quotes the real test output. Do not claim anything not run.
