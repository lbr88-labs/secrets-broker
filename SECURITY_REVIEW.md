# Security review: secrets-broker (lbr88-labs fork of otscup/secrets-broker)

- **Reviewed commit:** `366e4dd` (upstream `main`, 2026-10-23)
- **Review date:** 2026-11-22
- **Scope:** `server.mjs` (2,774 lines), `mcp-server.mjs` (stdio MCP adapter), `wh.mjs` (CLI helper), `deploy/*`, docs.
- **Method:** full manual read of the code paths, plus dynamic proof-of-concept tests against local instances running with a **fake `bw` binary** (it printed two dummy items and never contacted any vault). No real Bitwarden or Vaultwarden instance was touched. Telegram and ntfy were not configured during testing.
- **Planned deployment assessed:** Docker on the LAN in front of Vaultwarden, a dedicated read-only VW account, approvals on Android via ntfy or Telegram, `/mcp` exposed to remote harnesses (Claude Code, Codex, Cursor cloud agents, Grok Bot) through Cloudflare Tunnel + Access, and one agent token per AI agent.

## Verdict

**Not safe to pilot as reviewed (commit `366e4dd`).** The ranked fixes below have since been implemented on this fork; see [Remediation status](#remediation-status). The verdict and the proof-of-concept notes describe that reviewed commit, not the current tree.

The overall design is reasonable: one vault account, per-agent tokens, time-boxed grants and phone approval. The implementation has several flaws that each defeat the approval model by themselves:

- Anyone who messages the Telegram bot takes over the approval channel.
- Any user of the configured OIDC provider becomes admin.
- Approved requests keep returning the secret after the grant has been revoked or has expired.
- Read limits and "once" approvals can be raced.
- OAuth-registered agents can read every item and cannot be revoked.
- `exec_with_secrets` returns the secret to the model unmasked.

The project has one developer and was published a month ago, with 0 stars, 0 issues and no tests. In practice, we would be adopting this code and maintaining it ourselves.

## Ranked fix list (must-fix before a pilot)

| # | Fix | Severity | Status |
|---|-----|----------|--------|
| 1 | Telegram: never auto-rebind `chatId`. Only accept callbacks whose `from.id` and `message.chat.id` equal the configured chat/user ID. | Critical | Fixed, tested |
| 2 | OIDC: reject login unless `sub` equals the bound `oidcSub`. Allow binding only from an already-authenticated admin session. | Critical | Fixed, tested |
| 3 | Refuse to start without an admin password when bound to a non-loopback address. Remove the `isAdmin() → true` fallback and the `isLocal` trust. | Critical (config-dependent) | Fixed, tested |
| 4 | `/secret/pending/:id`: return a value only when there is an active grant, or a not-yet-consumed `once` approval. Expire and prune pending entries (for example, 10 min). | High | Fixed, tested |
| 5 | Make check-and-consume atomic (reserve the read or delete the `once` entry **before** the `await readItemValue`). | High | Fixed, tested |
| 6 | `/oauth/approve`: require the password (and TOTP if enabled), never TOTP alone. Rate-limit it. Gate or disable dynamic client registration. Make OAuth agents first-class (allowlist, revoke, list), or disable OAuth and use static agent tokens. | High | Fixed, tested |
| 7 | Default-deny allowlist (empty means nothing). Don't auto-create the `dsh/codex/hermes` agents. | High | Fixed, tested |
| 8 | `exec_with_secrets` and `wh.mjs run`: mask injected values in stdout/stderr, and strip `BROKER_AGENT_TOKEN`/`SECRETS_BROKER_TOKEN` from the child env. | High | Fixed, tested |
| 9 | ntfy: send links as ntfy `http` POST actions rather than GET links in the body, add a confirmation step, support an ntfy access token, and use a private self-hosted topic. | High | Fixed, tested |
| 10 | Write-enabled agents must not overwrite items outside their allowlist. | Medium | Fixed, tested |
| 11 | Random per-login admin session IDs with expiry, server-side logout, and the `Secure` cookie flag. | Medium | Fixed, tested (Secure is conditional; see M2) |
| 12 | `chmod 600` on `config.json`, `grants.json` and `audit.log`. Encrypt the TOTP secret. Don't use the `master-password` auto-unlock (or keep the key off the data volume). | Medium | Fixed, tested |
| 13 | Docker: run as a non-root `USER`, pin the base image by digest, and publish the port on `127.0.0.1` or the tunnel network only. | Medium | Fixed in the image files; not run here (no Docker daemon). `bw` CLI advisories are not patched. |

## Remediation status

Status of every finding against the current tree. "Tested" means `npm test` (`test/security.test.mjs`, fake `bw`, no real vault) fails if the behaviour regresses. Line numbers in the write-ups below still refer to `server.mjs` at `366e4dd`.

| Finding | Status |
|---|---|
| C1 Telegram takeover | Fixed, tested. Chat id and user id come from config or `TELEGRAM_CHAT_ID` / `TELEGRAM_USER_ID` and are never written from an update. A callback is acted on only when both are set and both match. |
| C2 OIDC account linking | Fixed, tested. `/oidc/login?bind=1` does not set the bind cookie unless the caller already has an admin session. Login requires the token `sub` to equal the stored `oidcSub`. `verifyIdToken` requires `exp` and does not fall back to the first JWKS key. |
| C3 Missing admin password / `isLocal` | Fixed, tested. `isAdmin` is a server-side session only. A non-loopback bind, `SECRETS_BROKER_BEHIND_PROXY=1`, or a non-loopback `BROKER_PUBLIC_URL` refuses to start when no admin password is set. Loopback with no password still starts, and every admin route returns 401. |
| H1 Read after revoke | Fixed, tested. A pending poll returns a value only while the grant is active, or for one `once` approval. Pending entries older than 10 minutes (`SECRETS_BROKER_PENDING_TTL_MS`) are deleted. |
| H2 Read-limit races | Fixed, tested. Grant reads are reserved and saved before `bw` runs, and rolled back if the read fails. A `once` entry is consumed before the read. Parallel `maxReads=1` and `once` polls each return the secret exactly once. |
| H3 TOTP-only approve | Fixed, tested. `/oauth/approve` requires the admin password and, when TOTP is on, a valid code. An admin cookie is not enough. `/login` and `/oauth/approve` have separate lockouts (5 failures, then 5 minutes). OAuth is off unless `SECRETS_BROKER_OAUTH=1` or `config.oauthEnabled`. |
| H4 OAuth reads everything | Fixed, tested. Dynamic registration is off unless OAuth is on, `SECRETS_BROKER_OAUTH_REGISTRATION=1` (or `config.oauthAllowRegistration`), and the caller is an admin. New OAuth agents start with an empty allow-list. Deleting `oauth:<clientId>` revokes the client and its tokens. |
| H5 exec output and token leak | Fixed for the original leak, with limits. Raw, base64, base64url, URL-encoding and hex are masked, including across `wh.mjs` chunk boundaries. The command's parent is started without the agent token, so `/proc/$PPID/environ` does not contain it. A prefix, reversed text, or the helper's own environment can still expose the value. |
| H6 Allow-all and default agents | Fixed, tested. An empty or missing allow-list matches nothing. `*` is the explicit allow-all pattern. A new install creates no agents. Existing `config.agents` entries are left in place. |
| H7 ntfy capability links | Fixed, tested. The ntfy body has no `/approve/` URL. Allow/deny are `http` POST actions with a one-time bearer token (`NTFY_TOKEN` or the encrypted settings token is sent as `Authorization: Bearer`). `GET /approve/:id` only shows a confirm form. Bot, secret and duration stay above the untrusted label; the reason and command sit under it. A private topic plus an Access bypass for `POST /approve/*` is a deployment choice; see the README. |
| M1 Write outside the allow-list | Fixed, tested. Creates and overwrites both require the name to match the allow-list. |
| M2 Admin session | Fixed, tested. Each login gets a random in-memory id (default TTL 12h, `SECRETS_BROKER_ADMIN_SESSION_TTL_MS`). Logout deletes that id. The cookie is `HttpOnly` and `SameSite=Strict`. `Secure` is set when `BROKER_PUBLIC_URL` is `https`, `x-forwarded-proto` is `https`, the socket is TLS, or `SECRETS_BROKER_COOKIE_SECURE=1`. Plain `http://127.0.0.1` omits `Secure` so a browser can store the cookie; `SECRETS_BROKER_COOKIE_SECURE=0` forces it off. Password comparison hashes both sides before `timingSafeEqual`. |
| M3 Files and the encryption key | Fixed, tested. The data directory is `0700` and config, grants, audit, agent tokens and the key file are `0600`. The TOTP secret and the ntfy token are encrypted in `config.json`. If `encryption.key` is inside the data directory, the on-disk `master-password` file is not used. `SECRETS_BROKER_MASTER_PASSWORD`, or a key from `SECRETS_BROKER_ENCRYPTION_KEY` / `SECRETS_BROKER_KEY_FILE` outside the data directory, still unlocks. The admin token-reveal API is unchanged. |
| M4 Prompt content | Partial. Trusted fields are separate from the clipped reason and the bot-supplied command, and bidi/zero-width characters are stripped. Each bot can have at most 5 pending requests. Names that are not in the vault can still be requested, up to that cap. |
| M5 Whole-vault decrypt | Not fixed. Every read still runs `bw list items`. |
| M6 Container | Partial. The Dockerfile uses `USER node` and pins `node:24-bookworm-slim` by digest. Both compose files publish `127.0.0.1:8788:8788`. The container still binds `0.0.0.0` so that publish works. Not run as a container in this environment. `@bitwarden/cli` advisories (multer, node-forge, tmp) are unchanged; the broker does not use `bw serve`. |
| M7 Restore makes a grant permanent | Fixed, tested. Restore clears `revokedAt` and resets `reads`, and leaves `expiresAt` as it was. An expired grant stays inactive until an admin sets a new expiry. |
| Low: loose URL match | Not fixed. `url=com` can still match `*.com`, subject to the allow-list and an active grant. |
| Low: auto-import | Fixed. `autoImport` defaults to false. A config that already sets `true` still imports. |
| Low: error leakage | Not fixed. `bw` stderr still reaches the admin UI, and an OIDC token error snippet can still appear on the login page. |
| Low: unbounded maps | Not fixed, except that pending requests older than the pending TTL are removed. `oauthCodes` and `loginFailures` are still in-memory maps with no cap. |
| Low: audit has no client IP | Not fixed. Secret values are still not written to the audit log. |
| Low: adapters and Cloudflare Access | Fixed, tested. `mcp-server.mjs` and `wh.mjs` send `CF-Access-Client-Id` and `CF-Access-Client-Secret` when both env vars are set. They no longer treat a stored `sha256:` hash as a bearer token and no longer default the agent name to `dsh`. |
| Low: HTTP MCP protocol, dead dashboard, licence string | Not changed. HTTP `/mcp` is still plain JSON `2024-11-05`. `dashboardShell` is still unused. `package.json` still says MIT while `LICENSE` says AGPL-3.0. |

`/login` and `/oauth/approve` use separate lockout buckets, both still keyed by the connecting IP. Behind one tunnel address, failed attempts can lock that one form for five minutes.

Our own deployment choices also need to change for the pilot:
- Use ntfy on a self-hosted, ACL-protected topic, or Telegram only after fix 1.
- Leave OIDC and dynamic OAuth off.
- Keep `MCP_ALLOW_READ` unset.
- Set `autoImport=false`.
- Use a Cloudflare Access service token per harness in addition to the agent token.
- Bypass Access for `POST /approve/*` only, so ntfy buttons still work. Keep `GET /approve/*` and every other path behind Access. Use a private self-hosted ntfy topic with an ACL.

---

## Findings

Severity is rated for the planned deployment. Line numbers refer to `server.mjs` unless another file is named.

### C1. Anyone can take over the Telegram approval channel (Critical)

**Status:** Fixed, tested. The notes below describe commit `366e4dd`.

`server.mjs:1724-1732`: any `message` update from **any** chat whose ID differs from the configured one overwrites `config.telegram.chatId` and saves it. Telegram bot usernames are public or guessable. An attacker sends `/start` to the bot, and from then on every approval prompt goes to the attacker's chat.

`server.mjs:1734-1752`: callback queries are acted on without checking `query.from.id` or `query.message.chat.id` against the bound chat. The handler only parses `apr:<id>:<decision>`.

Impact: a prompt-injected or malicious agent asks for `aws-root`, and the attacker taps "永久" (always) in their own Telegram. The real owner never sees the request. Even `TELEGRAM_CHAT_ID` set from env is overridden, because `config.telegram.chatId` takes precedence (`:1676`).

### C2. Any account at the OIDC provider becomes admin; binding is unauthenticated (Critical when OIDC is on)

**Status:** Fixed, tested. The notes below describe commit `366e4dd`.

- `server.mjs:1776, 1796`: `/oidc/login?bind=1` is reachable without authentication and sets `broker_oidc_bind=1`.
- `server.mjs:1830-1839`: if bind was requested **or** no `oidcSub` is stored yet, the callback stores the caller's `sub` as the owner.
- `server.mjs:1840-1844`: the admin cookie is then issued **without ever comparing** the token's subject to the bound `oidcSub`.

So any user who can authenticate at the issuer gets full admin, which includes minting agent tokens and approving their own requests. Examples are another Authentik user or open enrollment. `verifyIdToken` (`:761-787`) does check the signature, `aud`, `iss` and nonce. It only accepts ES256, falls back to the first JWKS key if `kid` doesn't match, and treats `exp` as optional.

### C3. No admin password means no authentication, including remotely on `/oauth/approve` (Critical when misconfigured)

**Status:** Fixed, tested. The notes below describe commit `366e4dd`.

- `server.mjs:700-704`: `isAdmin()` returns `true` when no admin password is set.
- The admin UI is then "local only" by `req.socket.remoteAddress` (`:1763`, `:2015-2020`). This check is not applied to the OAuth routes, which are handled earlier (`:1885-1982`).
- **PoC (verified):** against an instance with no admin password, `POST /oauth/approve` with no password at all returned `302 Location: https://attacker.example/cb?code=…`. Any remote party can therefore mint an OAuth access token, which is a full agent identity (see H4).
- The `isLocal` trust also breaks behind proxies. If cloudflared runs in host networking and reaches the broker on 127.0.0.1, every tunnel request counts as "local" and gets admin. With no password, the local admin API is also open to CSRF and DNS rebinding from any web page in a local browser, since there is no Host or Origin check.

`.env.example` ships `SECRETS_BROKER_ADMIN_PASSWORD=change-me`, and the server does not refuse to run when `BIND=0.0.0.0` without a password.

### H1. Revocation and expiry bypass through `/secret/pending/:id` (High)

**Status:** Fixed, tested. The notes below describe commit `366e4dd`.

- `server.mjs:2688-2702`: once a request is `approved`, polling `/secret/pending/<id>` returns the secret value. The handler checks only `entry.status === 'approved'` and the allowlist. It does **not** check that a grant is still active.
- Pending entries live in memory forever (`state.pending`, `:289`, `:1484-1547`). Only `once` entries are ever deleted (`:2697`).
- **PoC (verified):** an admin approved `1h`, then revoked the grant (and in a second run deleted it entirely). `GET /secret` correctly went back to `pending`, but `GET /secret/pending/<old-id>` still returned `{"value":"GW-SECRET-1234"}`. The same applies after the 1h/24h/7d expiry. Reads through this path also don't increment `reads`, so `maxReads` doesn't apply either.

A tricked agent that has kept its request ID keeps access until the broker restarts.

### H2. `maxReads` and "once" approvals are race-able (High)

**Status:** Fixed, tested. The notes below describe commit `366e4dd`.

- `server.mjs:2723-2730` (and the MCP path `:2635-2641`): `validGrant()` is checked, then the code waits on `readItemValue()` (a `bw list items` subprocess, roughly 0.5–2 s), and only then increments `reads`.
- `server.mjs:2696-2697`: a `once` approval is deleted only **after** the value has been read.
- **PoC (verified, fake `bw` with 400 ms latency):**
  - A grant with `maxReads=1` served **8 of 8** concurrent reads.
  - A `once` approval served **6 of 6** concurrent polls.

### H3. `/oauth/approve` accepts TOTP alone and has no rate limit (High)

**Status:** Fixed, tested. The notes below describe commit `366e4dd`. `/login` and `/oauth/approve` now have separate per-IP lockouts. A shared tunnel address can still lock one of those forms.

`server.mjs:1931-1938`: authorization is granted if the request has an admin cookie, **or** the password matches, **or** a valid TOTP code is given (6 digits, ±1 window, `:1660-1667`). TOTP alone is a single 6-digit factor with about 3 valid codes at any moment. Neither branch goes through `loginThrottle`.

**PoC (verified):** 12 consecutive wrong passwords were all processed, with no 429. Online brute force of the TOTP gets an attacker an OAuth agent token. The `/login` throttle does work after 5 attempts (verified). Behind a tunnel, however, all clients share the proxy's IP, so an attacker can also lock the owner out (`:154-170`).

### H4. OAuth agents read everything and can't be scoped or revoked; client registration is open (High)

**Status:** Fixed, tested. The notes below describe commit `366e4dd`.

- `/oauth/register` (`:1885-1913`) is unauthenticated, accepts any `redirect_uris`, and writes to `config.json` without limits (disk-fill DoS).
- An approved client becomes the agent `oauth:<clientId>` (`:1967`, `:1291`).
- `agentAllowed()` treats a missing allowlist as **all items** (`:1311-1315`). The admin endpoints for allowlist, write, rotate and delete all require `config.agents[name]` (`:2193`, `:2204`, `:2217`), so they return `unknown agent` for OAuth agents.
- **PoC (verified):** an OAuth token listed all vault items. Setting an allowlist and deleting the agent both failed with `{"error":"unknown agent"}`.
- Tokens last 24 h, there is no revoke endpoint, and the only remedy is to edit `config.json` and restart. `scope` and `resource` are not enforced.

### H5. `exec_with_secrets` doesn't mask output and passes the agent token to the child (High)

**Status:** Fixed for the original leak, with the limits in the remediation table. The notes below describe commit `366e4dd`. HTTP `get_secret` still returns plaintext when `MCP_ALLOW_READ=1`.

- `mcp-server.mjs:142-157`: the secret is injected into the child env, and the child's raw stdout and stderr are returned to the model. Nothing is masked.
- The child also inherits the whole `process.env`, including `BROKER_AGENT_TOKEN`. The same applies to `wh.mjs:107` (`SECRETS_BROKER_TOKEN`).
- **PoC (verified):** `exec_with_secrets {command:"sh", args:["-c","echo X=$X; env | grep BROKER_AGENT_TOKEN"], vars:{X:"gatewayapi"}}` returned `X=GW-SECRET-1234` and the agent token in the MCP result.
- The command is agent-chosen, so a single `printenv` exposes the secret. The "the model never sees the value" claim in the README and docs is false.
- `exec_with_secrets` exists only in the stdio adapter. Remote harnesses using `/mcp` over HTTP can only get values through `/secret` (raw JSON) or `get_secret`. In the planned remote setup, the value always reaches the agent.

### H6. Allow-all defaults and three pre-created agents (High)

**Status:** Fixed, tested. The notes below describe commit `366e4dd`. `noApprovalItems` still skips approval for names an admin listed.

- Empty allowlist means all items (`:1313`).
- First start auto-creates agents `dsh`, `codex` and `hermes` with live tokens (`:175`, `:209`).
- Items flagged `noApprovalItems` bypass approval completely (`:2635`, `:2724`).

### H7. ntfy approval links are bearer capabilities sent in clear text in the push body (High for public or unauthenticated ntfy)

**Status:** Fixed, tested. The notes below describe commit `366e4dd`. A private topic is still an operator choice.

- **Scheme:** `HMAC-SHA256(SESSION_SECRET, "id|decision|exp")` (`:1549-1556`), with a constant-time compare (`:1864`), a 10-minute expiry, and effectively one-time use because `decideRequest` requires `status === 'pending'` (`:1530`). The decision is inside the signature, so "once" cannot be upgraded to "always". These parts are sound.
- **But:** the three links (`once`, `24h`, `deny`; no 1h/7d/always) are embedded as text in the ntfy message (`:1498-1503`). The broker sends no `Authorization` header to ntfy (`:1520-1524`), so the topic must be anonymously writable. Anyone who can read the topic can approve, and on ntfy.sh topics are public by name.
- `/approve/:id` is a state-changing **GET** with no confirmation page (`:1857-1871`), so link scanners or prefetchers can approve.
- Approvals by link record only `source: 'ntfy'`, with no IP or user.
- `SESSION_SECRET` is random per process (`config.adminSessionSecret` is never written), so a restart invalidates links. That is fine.

### M1. Write-enabled agents can overwrite any item, including ones they can't read (Medium)

**Status:** Fixed, tested. The notes below describe commit `366e4dd`.

`/agent/items/save` and MCP `create_secret` (`:2666-2687`, `:2610-2623`) check only `agentWrite`. `saveItem` (`:398-421`) finds the item by name (case-insensitive) and replaces its password, notes and URL. The allowlist is not consulted.

Impact: a write-enabled agent could swap another service's credential or URL, for example to redirect a webhook. Writes are off by default, and against a read-only VW collection they would fail.

### M2. Admin session design (Medium)

**Status:** Fixed, tested. The notes below describe commit `366e4dd`. `Secure` is omitted on plain HTTP so a local browser can store the cookie.

- The admin cookie is a constant: `HMAC(SESSION_SECRET, 'admin-session')` (`:687-689`).
- Every login gets the same value, and logout only clears the browser copy. **PoC (verified):** the old cookie still worked after logout.
- The cookie has no `Secure` flag and no expiry (`:2007`, `:1844`).
- The password compare is not constant-time (`:1996`, `:1933`).
- `SameSite=Lax` blocks cross-site POST CSRF while a password is set. However, `GET /api/oidc/discover?issuer=` is an admin-only server-side fetch that can be triggered by top-level navigation (blind SSRF, Low).

### M3. Secrets at rest (Medium)

**Status:** Fixed, tested. The notes below describe commit `366e4dd`. The admin token-reveal API still returns a plaintext agent token to a logged-in admin.

- `config.json`, `grants.json` and `audit.log` are written with default permissions, which was **0644** in the test (`:211`, `:229`, `:249`, `:253`).
- `config.json` holds the TOTP secret in plaintext, the admin password if it is set there, the OAuth client list and token hashes.
- The AES-GCM "at-rest encryption" key sits next to the data (`/data/encryption.key`, `:54-61`). That makes the encrypted `master-password` auto-unlock file (`:135-152`) plaintext-equivalent for anyone who can read the volume. Combined with `BW_CLIENTID`/`BW_CLIENTSECRET` in `.env`, that means the whole vault. The docs say so; don't enable auto-unlock.
- Agent tokens are recoverable in plaintext through the admin API (`/api/agents/token`, `:2122-2130`).

### M4. Approval prompt shows an agent-controlled string and no context (Medium)

**Status:** Partial. Trusted fields are separated from the reason and the command, bot text is capped, and each bot is limited to 5 pending requests. The notes below describe commit `366e4dd`.

- The push shows the agent name (trusted, derived from the token) and the item name, which is **agent-supplied**.
- `validName` (`:293-302`) blocks control characters and a leading `-`, but allows 160 characters of anything else: Unicode bidi overrides (verified: `U+202E` passes), spaces, and URLs.
- Telegram uses plain text, so there's no markup injection.
- There is no reason or command field at all. Trusted and untrusted parts are therefore not separated, and the approver has no context about why the secret is wanted.
- Requests for names that don't exist still send pushes (`:1484-1493`). Only identical *pending* (agent, name) pairs are de-duplicated, so an agent can flood the phone with distinct names, which invites approval fatigue.

### M5. Whole vault decrypted on every read (Medium)

**Status:** Not fixed.

`readItemValue` (`:471-481`) runs `bw list items` and searches it, so every read decrypts **every** item into the Node heap. `itemsCache` (`:380-389`) keeps the full objects, passwords included, until it is replaced. Duplicate names resolve to the first match, case-insensitively, which allows item shadowing if someone else can write to the shared collection.

### M6. Container and dependencies (Medium)

**Status:** Partial. Non-root user, digest pin and loopback publish are in the image files. `bw` CLI advisories are not patched. The notes below describe commit `366e4dd`.

- `deploy/Dockerfile` has no `USER`, so it runs as **root**. `node:24-bookworm-slim` is not pinned by digest. `SECRETS_BROKER_BIND=0.0.0.0`, and the compose files publish `8788:8788` on all host interfaces.
- The project itself has **no npm dependencies**. The image installs `@bitwarden/cli@2026.10.0`. `npm audit` on that version gives **4 high and 2 low**:
  - `multer` (2 DoS advisories, only used by `bw serve`, which is not used here)
  - `node-forge` (GHSA-86w9-cpqp-85rv, GHSA-4642-5mcj-2rqw)
  - `tmp` (GHSA-52f5-9888-hmc6, GHSA-ph9p-34f9-6g65)
  - `inquirer`/`external-editor` (low)
- The latest `@bitwarden/cli@2026.11.0` has the same 6 findings. Because the broker only spawns `bw` with fixed arguments, exploitability is low. Track upstream.
- `pip-audit` and `govulncheck` don't apply (no Python or Go).

### M7. `restoreGrant` turns an expired grant into a permanent one (Medium)

**Status:** Fixed, tested. Restore no longer clears `expiresAt`. The notes below describe commit `366e4dd`.

`server.mjs:624-635`: "Restore" on an expired grant sets `expiresAt = null` (forever) and resets `reads` to 0.

### Low / informational

**Status:** Cloudflare Access headers, the sha256 token fallback, and the `autoImport` default are fixed. See the remediation table for what is still open. `autoImport` defaults to false.

- **Loose URL matching** (`:450-457`): `/secret?url=com` matches any `*.com` item. **Verified:** `url=com` matched `aws.amazon.com`. It is still subject to the allowlist and grants.
- **Auto-import writes to the vault** (`:514-559`, run on every unlock `:353`): it reads `~/.dsh-home/.env`, `.credentials.yaml` and `mcp-auth/mcp-token.json` and creates vault items. This is specific to the author's setup; set `autoImport: false`.
- **Error leakage:** `bw` stderr is returned to the admin. The OIDC token-endpoint error body (200 characters) is shown on the unauthenticated login page (`:1821`, `:1853`).
- **Memory DoS:** `oauthCodes`, `state.pending` and `loginFailures` are unbounded in-memory maps. `/api/audit` and `/api/stats` read the whole audit log on every call.
- **Audit:** values never appear in the audit log; **verified** with 0 matches for secret values after all tests. Agent-read entries lack the client IP, and the log is not tamper-evident.
- **Adapter integration:** `mcp-server.mjs` and `wh.mjs` send only `Authorization: Bearer`. They cannot send `CF-Access-Client-Id`/`Secret`, so they won't pass Cloudflare Access without a patch. `mcp-server.mjs:29-33` falls back to reading `config.agents[agent]`, which is now a sha256 hash, so that fallback is broken.
- **HTTP `/mcp`:** speaks protocol `2024-11-05` as plain JSON, without batching or SSE. `get_secret` is off unless `MCP_ALLOW_READ=1` (`:2582`), which is a good default.
- **Command injection:** none found in the server. `bw` is spawned with an argument array and no shell, and `validName` blocks option injection. `exec_with_secrets` executes an agent-chosen command by design.
- **SSRF:** no agent-controlled URL is fetched. All server-side fetches go to admin-configured URLs (OIDC, ntfy, Gotify, WxPusher, Telegram).
- **XSS:** the live dashboard (`dashboardShellV2`) escapes agent-controlled fields, and I found no injection. About 600 lines of an older dashboard (`dashboardShell` `:789`, `dashboard` `:1317`) are dead code.
- **Licence mismatch:** `package.json` says MIT, while `LICENSE`/README say AGPL-3.0 (relicensed in `e7fa432`).

## Per-agent isolation: what holds

These were verified with two agents:
- Agent B polling agent A's request ID gets `404 unknown request` (`:2691`).
- Grants are keyed by (agent, name).
- An agent bearer token on `/api/requests/:id/decide` gets the login page, not an approval. The request stayed pending until the admin decided.
- Agents have no path to the admin API while an admin password is set and the agent isn't connecting from loopback.

The isolation weaknesses are the ones above: OAuth agents (H4), Telegram (C1), OIDC (C2), and the no-password or `isLocal` trust (C3).

## Outbound network calls

The code makes outbound calls only to:
- the `bw` CLI → `BW_SERVER`
- `api.telegram.org` (if configured)
- `NTFY_URL`, `GOTIFY_URL`, `WXPUSH_URL` (WxPusher is a WeChat push relay; if configured)
- the OIDC issuer, JWKS and token endpoints (if configured)

There is **no telemetry**, and the dashboard loads no external scripts or fonts. The README links to a hosted demo (`demo.otscup.com`) and companion repos, but nothing calls them.

## Code size, tests, maintenance

- About 3,100 lines of JS in three files, with no dependencies. `server.mjs` is a 2,774-line monolith with inline HTML/JS and Chinese UI strings.
- **No tests.** CI only runs `node --check` and a `docker build`.
- History is 15 commits by a single author (`otscup`) over 2026-10-19 → 2026-10-23. The initial commit added 3,276 lines in one go, and nothing has been pushed since 2026-10-22.
- Upstream has 0 stars, 0 issues and 1 fork (this one). The author account has 94 public repos and 0 followers.
- The code looks rapidly generated. Several features (OIDC, OAuth, TOTP, Gotify/WxPusher) were bolted on within hours, and that is where most of the critical bugs are.
- **Maintenance risk: high.** Treat it as a starting point we own, not as a maintained upstream.

## How the PoCs were run

The PoCs used two local instances, one with an admin password and one without. Each had its own temporary `SECRETS_BROKER_HOME`, `SECRETS_BROKER_BW` pointed at a 15-line fake `bw.js` that returned two dummy items after a 400 ms delay, and auto-unlock with a dummy password. ntfy and Telegram were unset, all traffic stayed on 127.0.0.1, and both instances were stopped afterwards. No real vault, Bitwarden or Vaultwarden was contacted.
