# Antigravity MCP: long-running tasks (async task lifecycle)

Implement this spec exactly. Work only in `src/index.ts` and `test/index.spec.ts`, plus `README.md` for the tool list. Do not touch `.github/`, `wrangler.jsonc`, `package.json`, `package-lock.json`, or any consent, OAuth, CSRF, passphrase, throttle or Durable Object code.

## 1. Problem

`callAntigravityAgent` creates an interaction, then polls inside one MCP tool call for at most about 120 seconds (60 polls). If the agent is still running, it throws and the result is lost. Long agent tasks therefore cannot finish through this server.

## 2. Google API facts to rely on (Interactions API, `https://generativelanguage.googleapis.com/v1beta/interactions`)

- `POST /interactions` with `"background": true` returns an interaction `id` immediately while the server keeps running the task.
- Background execution requires `store: true`. `store: false` disables it. Always send `store: true` together with `background: true`.
- `GET /interactions/{id}` returns the current state (poll this).
- `POST /interactions/{id}/cancel` cancels a background interaction that is still running; it returns the interaction resource.
- Keep the existing agent id, request headers (`x-goog-api-key`) and payload shape (`agent`, `input`, `environment`, `tools`, `system_instruction`). Do not add new headers.

## 3. Design

### 3.1 Split the Google calls (module-level functions in `src/index.ts`)
- `createInteraction(apiKey, payloadInputs, env)`: builds the existing payload (reuse the current code for prompt, workspace files, repo context, system instruction, credential checks) and sends it with `background: true` and `store: true`. Returns the parsed interaction. Does not poll.
- `getInteraction(apiKey, id)`: one GET.
- `cancelInteraction(apiKey, id)`: one POST to `/cancel`.
- `waitForInteraction(apiKey, interaction, waitMs, pollIntervalMs)`: polls `getInteraction` until the status is terminal or the deadline passes. Returns the latest interaction either way. It never throws just because the deadline passed.
- Keep `sanitizeSecret` on every error message. Keep the existing per-request fetch timeout (60 s).
- Keep `validateWorkspaceFiles`, `validateAndNormalizeRepoOptions`, credential-id validation and the repo-mode fail-closed behavior byte-for-byte equivalent. Repo modes must still fail with the current "credential not configured" errors when the credential ids are unset.

### 3.2 Statuses
- Terminal: `completed`, `failed`, `cancelled`, `incomplete`.
- `requires_action`: not terminal for waiting purposes; return it to the caller with its status (do not throw "unsupported").
- Any status not in the known list is NOT an error: treat it as non-terminal, return it as-is. Remove the throw on unknown status from `validateInteractionData` (keep the object-shape check and the `status` string check).

### 3.3 Task index (best effort, no new bindings)
Use the existing `OAUTH_KV` binding with the key prefix `antigravity:task:`.
- Key: `antigravity:task:<taskId>`. Value (JSON): `{ taskId, createdAt (ISO), updatedAt (ISO), status, mode (inspect/review/propose/implement or "plain"), repository?, ref?, pullRequest?, taskPreview (first 200 characters of the task), lastError? (sanitized, max 500 characters) }`. Also store `{ createdAt, status, mode }` as KV metadata so listing needs no extra reads.
- `expirationTtl`: 30 days. Refresh the record (put again) when a later call sees a changed status.
- Index failures must never fail a tool call: catch, `console.warn` a short reason with no prompt text, no output text and no secrets, and continue.
- A `taskId` must match `^[A-Za-z0-9_-]{1,200}$` before it is used in a URL or a KV key. Otherwise return an `isError` tool result with a clear message.
- Tools must also work for a valid `taskId` that is not in the index (query Google directly; skip index updates if there is no record).

### 3.4 Output shaping (shared helper)
`formatTaskResult(interaction, { offset, includeRaw })` returns a JSON text with: `taskId`, `status`, `done` (boolean, terminal), `outputText` (the `output_text` field when present), `error` (sanitized message when failed), `usage` (if present on the interaction), `truncated`, `totalChars`, `nextOffset` (when more text remains).
- At most 60,000 characters of `outputText` per response; `offset` (integer >= 0) pages through the rest.
- If there is no `output_text` on a completed interaction, include the raw interaction JSON (sanitized, same 60,000 character cap and offset rules) as `rawFallback`.
- `includeRaw: true` returns the raw interaction JSON (sanitized, capped) as `raw`.
- Never include the API key; run `sanitizeSecret` over everything that comes from Google.

### 3.5 MCP tools (all registered in `createAntigravityMcpServer`, all behind the existing auth and scope)

| Tool | Inputs | Behavior |
|---|---|---|
| `run_antigravity_agent` (existing name kept) | existing inputs plus `waitSeconds` (int 0-90, default 45) | Creates a background interaction, indexes it, waits up to `waitSeconds`. If terminal and `completed`: returns the formatted result. If failed, cancelled or incomplete: `isError: true` with the reason and the `taskId`. If still running at the deadline: returns a NON-error result with `status: "in_progress"`, the `taskId`, and a message telling the caller to call `get_antigravity_task`. |
| `start_antigravity_task` | same inputs as `run_antigravity_agent` except `waitSeconds` | Creates and indexes the interaction, returns `taskId` and `status` immediately. |
| `get_antigravity_task` | `taskId`, `waitSeconds` (int 0-90, default 20), `offset` (optional), `includeRaw` (optional) | Fetches the interaction (waits up to `waitSeconds` if it is still running), updates the index, returns the formatted result. |
| `cancel_antigravity_task` | `taskId` | Calls cancel, updates the index, returns the new status. A cancel on an already-finished task returns its current status and does not fail. |
| `list_antigravity_tasks` | `limit` (int 1-50, default 20), `status` (optional filter) | Lists indexed tasks newest first using KV list metadata (follow KV cursors until `limit` is satisfied or 1,000 keys have been scanned). Returns `taskId`, `status`, `createdAt`, `mode`, `taskPreview` per item. Statuses in the list are as of the last time the task was fetched; say so in the tool description. |

Tool descriptions must tell the caller: "long tasks: call get_antigravity_task with the taskId until done is true".

### 3.6 Keep as is
Repo-mode handling, the `implement` system instruction and its branch-protection note, workspace file limits, the default agent id, CORS, auth, consent flow. `implement` mode must remain impossible without the write credential id configured.

## 4. Tests (`test/index.spec.ts`)
Mock `fetch` as the existing tests do. Waiting must not slow the suite: make the poll interval and wait deadline injectable (parameters with defaults) or use fake timers. Cover at least:
1. create sends `background: true` and `store: true`, returns the id without polling.
2. `run_antigravity_agent`: completed within the wait returns the text; still `in_progress` at the deadline returns a non-error result containing `taskId`; `failed` and `cancelled` return `isError`.
3. `get_antigravity_task`: in_progress then completed across polls; unknown status is returned, not thrown; `requires_action` returned as-is.
4. `cancel_antigravity_task` sends POST to `/interactions/<id>/cancel`; cancel of a finished task does not fail.
5. `list_antigravity_tasks`: newest first, `limit`, `status` filter, KV cursor handling.
6. KV failure (get, put, list throwing) does not fail `start`, `run` or `get`.
7. Invalid `taskId` (path characters, empty, too long) is rejected before any fetch or KV call.
8. Output paging: `offset`, `truncated`, `nextOffset`, `totalChars`; raw fallback when there is no `output_text`.
9. The API key never appears in any returned text or console output, including error paths (use a distinctive key and assert).
10. Repo modes still fail closed when the credential ids are unset; `implement` without the write credential id fails.

Existing tests that asserted the old timeout throw or the unknown-status throw must be changed to the new behavior. List every changed existing test and the reason in the PR body.

## 5. Acceptance
- `npx tsc --noEmit` (or the repo's type-check script) and the full vitest suite pass; report the real output.
- No edits outside `src/index.ts`, `test/index.spec.ts`, `README.md`.
- No new dependencies, no new bindings, no new environment variables.
- The final message lists every file touched and every existing test changed.
