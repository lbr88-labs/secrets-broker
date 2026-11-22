# Secrets Broker

[English](README.md) | [简体中文](README.zh-CN.md)

[![CI](https://github.com/otscup/secrets-broker/actions/workflows/ci.yml/badge.svg)](https://github.com/otscup/secrets-broker/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](package.json)

A small, self-hosted **secrets broker for AI agents**. It stores credentials in any
Bitwarden-compatible vault (NodeWarden, Vaultwarden, Bitwarden), and gives agents a
narrow API/MCP surface with per-agent tokens, explicit approvals, short-lived grants,
read limits and an audit log.

The important property: **the model never needs to see a secret**. Agents (or
connectors/plugins) ask the broker; the broker asks the human; the human approves once,
for an hour, a day, a week or forever. Every read is attributed to an agent and logged.

## Cloudflare Workers version

A Cloudflare Workers-native port lives at
<https://github.com/otscup/secrets-broker-workers>. It reads NodeWarden's D1
directly, performs KDF in the browser, keeps the session in a Durable Object and
supports MCP OAuth 2.1, agent tokens, folder isolation and cross-account copies.
No NAS, Docker or tunnel is required.

The portable agent skill and stdio MCP bridge are at
<https://github.com/otscup/secrets-broker-skill>.

## Why

AI agents routinely need API keys, cookies, passwords and tokens. Pasting them into
prompts, `.env` files or tool configs is hard to audit and easy to leak. This project
keeps the vault where humans already manage it (Bitwarden clients, backups, 2FA) and
adds the missing agent-facing control plane.

- **Vault-native**: uses the Bitwarden CLI against your existing vault. No new
  encrypted database to operate.
- **Human in the loop by default**: first access opens a pending approval. Approve once, for a
  limited time, or permanently; revoke or restore later. Common items can be put in
  **no-approval mode** (audit-only) when you prefer frictionless access.
- **Per-agent identities**: each agent gets its own token (hashed at rest), item
  allowlists and optional write access. Rotate/delete independently.
- **Audit-first**: who requested what, when, from which channel, and how many reads.
- **Multiple approval channels**: web UI, ntfy, Telegram inline buttons, Gotify,
  wxpush (WeChat), or signed one-time links that need no login.
- **MCP native**: stdio adapter and a Streamable HTTP endpoint with OAuth 2.1
  discovery, dynamic client registration, PKCE and a browser consent page.

## Try it before installing

<https://demo.otscup.com> runs the same idea against a virtual vault: no install,
no NodeWarden, no real credentials. Its own OIDC provider makes the whole flow —
approve a request, read a key, watch the audit line — clickable in a minute. The
demo resets itself, so poke at whatever you like.

## Features

- Web dashboard: overview/charts, items (name, URL, group), search, edit, share,
  agents, grants, logs, profile/2FA, settings.
- URL matching: items can store a website; agents can ask by URL/hostname.
- Per-item **no-approval mode**: reads are returned immediately, but every read is
  still counted and audited (`mode=no-approval`). Useful for common sites/logins.
- Grants: once / 1h / 24h / 7d / permanent, optional read-count limit, extend,
  custom expiry, revoke, restore.
- Approval request headers include signed links valid for 10 minutes.
- Agent HTTP API: `GET /secret?name=...` or `GET /secret?url=...`.
- MCP:
  - HTTP: `POST /mcp` (JSON-RPC), OAuth 2.1 or Bearer token.
  - stdio: `mcp-server.mjs` (also supports `exec_with_secrets`, injecting secrets
    into a child process without exposing them to the model).
- At-rest hardening:
  - AES-256-GCM for the auto-unlock password, OIDC/Telegram/Gotify/wxpush secrets
    and the local token-reveal file.
  - Agent tokens stored as SHA-256 hashes in `config.json`.
  - Login throttling and optional TOTP (2FA) for the admin account.
- Optional OIDC login (passkeys supported by the identity provider, e.g. xid).
- Docker image, Compose file and a small dependency-free Node service.

## Quick start (Docker)

```bash
git clone https://github.com/lbr88-labs/secrets-broker.git
cd secrets-broker
./deploy/install.sh
```

The installer asks for the vault URL, API key, admin password and public URL,
writes `deploy/.env`, then runs `docker compose up -d --build`.

The Docker image installs `@bitwarden/cli` inside the container — you do **not**
need `bw` on the host and nothing is installed outside Docker. The image is
larger (Node base + Bitwarden CLI), but there is only one container and one
volume.

Manual path:

```bash
cp deploy/.env.example deploy/.env
# edit deploy/.env
docker compose up -d --build
```

Open `http://127.0.0.1:8788/`, log in with `SECRETS_BROKER_ADMIN_PASSWORD`, then
enter your vault master password to unlock. The published port is loopback-only.
Inside the container the process listens on `0.0.0.0` so that mapping works, and
it runs as the `node` user (uid 1000). `data/` must be writable by that user.

Do not leave a `master-password` file next to `encryption.key`. On-disk
auto-unlock is refused while the key lives in the data directory. Unlock with
`SECRETS_BROKER_MASTER_PASSWORD`, or move the key to `SECRETS_BROKER_ENCRYPTION_KEY`
/ `SECRETS_BROKER_KEY_FILE` (a Docker secret or a path outside the volume) before
using the file.

Data lives in `data/` (mounted as `/data` in the container): `config.json`,
`grants.json`, `audit.log`, `encryption.key`, optional `master-password` and the
encrypted `agent-tokens.json`.

> Back up `encryption.key` together with `data/`; losing it makes encrypted fields
> unrecoverable.

## Local run (Node 20+)

```bash
npm start          # server on 127.0.0.1:8788
npm run mcp        # stdio MCP adapter
```

Prerequisites: the `bw` CLI (or set `SECRETS_BROKER_BW` to its JS entry point) and a
Bitwarden-compatible vault.

## Agent API

```bash
# Read by item name (opens an approval request on first access)
curl -H "Authorization: Bearer $AGENT_TOKEN" \
  "https://broker.example.com/secret?name=tavily-api-key"

# Read by website/hostname
curl -H "Authorization: Bearer $AGENT_TOKEN" \
  "https://broker.example.com/secret?url=https://example.com"

# Agent write access (enable "write" for that agent in the UI first)
curl -X POST -H "Authorization: Bearer $AGENT_TOKEN" -H 'content-type: application/json' \
  -d '{"name":"project/prod/api-key","value":"...","url":"https://example.com","group":"projects"}' \
  "https://broker.example.com/agent/items/save"
```

Tokens are managed in the UI (Agents): copy/reveal, rotate, allowlist, write toggle.

## MCP

### HTTP (Streamable HTTP)

```
https://broker.example.com/mcp
```

Two authentication modes:

1. **OAuth 2.1 (no API token)**: clients discover
   `/.well-known/oauth-protected-resource` and
   `/.well-known/oauth-authorization-server`, register dynamically, open a browser
   consent page and exchange a PKCE code for a 24h access token.
2. **Bearer token**: `Authorization: Bearer <agent token>`.

Tools: `list_secrets`, `create_secret`, `request_access`, and optional `get_secret`
(disabled by default; set `MCP_ALLOW_READ=1`).

### stdio

```json
{
  "mcpServers": {
    "secrets": {
      "command": "node",
      "args": ["/path/to/secrets-broker/mcp-server.mjs"],
      "env": {
        "BROKER_URL": "https://broker.example.com",
        "BROKER_AGENT_TOKEN": "<agent token>"
      }
    }
  }
}
```

The stdio adapter adds `exec_with_secrets`, which injects secrets into a local child
process environment. Returned stdout and stderr have the secret and its base64,
base64url, URL-encoded and hex forms replaced with `[redacted]`, including when
the value is split across writes. `wh.mjs` does the same. The command's parent
process is started without `BROKER_AGENT_TOKEN`, `SECRETS_BROKER_TOKEN`, the
Cloudflare Access service token, or the admin, master and encryption-key
variables, so `/proc/$PPID/environ` does not contain them.

That masking is a guard against accidents. A command can still print a prefix,
a reversed or spaced value, or an encoding of the value plus extra text. The
helper that launched the parent still has the original environment, and the
token is also in the harness MCP config and in the helper's memory. Set
`BROKER_AGENT_TOKEN` explicitly; a stored `sha256:` hash is not used as a bearer
token.

## Notifications

All optional. Configure in the UI (Settings) or via environment:

- **ntfy**: private topic URL plus `NTFY_TOKEN`. The push carries `http` POST action buttons, not links in the body.
- **Telegram**: bot token, chat id and user id. Both ids must be configured. The bot sends inline buttons (approve once / 1h / 24h / 7d / permanent / deny); callbacks are handled by long polling and ignored unless `from.id` and `message.chat.id` match.
- **Gotify**: server URL + app token.
- **wxpush**: `WXPUSH_URL` + API token; sends WeChat notifications via
  [wxpush](https://github.com/frankiejun/wxpush).

## Secure deployment

Use this shape for a pilot. The defaults now match it: OAuth is off, a new
install creates no agents, and an empty allow-list matches nothing.

- Leave OIDC unset. Leave OAuth unset (`SECRETS_BROKER_OAUTH` is not `1`, and
  `config.oauthEnabled` is not `true`). Dynamic client registration stays off
  unless OAuth is on, `SECRETS_BROKER_OAUTH_REGISTRATION=1`, and the request
  carries an admin session cookie.
- Leave `MCP_ALLOW_READ` unset. `get_secret` returns the value to the model.
- Do not enable on-disk auto-unlock. `autoImport` now defaults to false, so
  unlock does not write the author's local credential files into the vault.
  An existing config that sets `"autoImport": true` still imports.
- Put Cloudflare Access in front of the public hostname. Give each harness its
  own Access service token and set `CF_ACCESS_CLIENT_ID` and
  `CF_ACCESS_CLIENT_SECRET` on `mcp-server.mjs` and `wh.mjs`. Those two headers
  are added only when both variables are set. Keep a separate agent token per
  harness as well.
- Bypass Access for `POST /approve/*` only. ntfy action buttons are HTTP POSTs
  from the ntfy app and do not send an Access cookie or service token. The POST
  is still gated by a one-time bearer token. Keep `GET /approve/*` and every
  other path behind Access. Do not put the whole `/approve/` prefix behind
  Access, or the phone buttons stop working.
- If a tunnel reaches a process that is bound to `127.0.0.1`, set
  `SECRETS_BROKER_BEHIND_PROXY=1`. A non-loopback `BROKER_PUBLIC_URL` is treated
  the same way. Either one, or a non-loopback bind, refuses to start unless
  `SECRETS_BROKER_ADMIN_PASSWORD` is set.
- Run ntfy yourself. ACL the topic so only your user can read it and only the
  broker's token can write it, and set `NTFY_TOKEN` (or the token field in
  Settings). The one-time approval tokens sit in the ntfy `Actions` header, so
  anyone who can read the topic can approve for about 10 minutes. Approvals are
  `http` POST buttons. The message body does not contain an `/approve/` URL.
  The bot-supplied reason and command are below an untrusted-text label.
  Opening the signed link in a browser shows a confirm form; the decision is a
  `POST`. Configure Telegram with both `TELEGRAM_CHAT_ID` and
  `TELEGRAM_USER_ID`. Incoming messages never change those ids.
- Give every agent an allow-list (`*` means every item). An empty list is no
  access, including writes. The UI checkbox "全部条目" saves `*`.

The admin cookie is `HttpOnly` and `SameSite=Strict`, one random id per login,
and it is deleted on logout. `Secure` is added when `BROKER_PUBLIC_URL` is
`https://` (or the request is HTTPS). On plain `http://127.0.0.1` it is omitted
so a browser can keep the session; set `SECRETS_BROKER_COOKIE_SECURE=1` to force
it. `/login` and `/oauth/approve` have separate per-IP lockouts (5 failures, then
5 minutes). A tunnel that shows every client as one address can still lock that
one form. A bot can have at most 5 pending approval requests at a time.

Default listen address outside Docker is `127.0.0.1`. The image listens on
`0.0.0.0` and Compose publishes `127.0.0.1:8788:8788`.

## Security model (summary)

- Vault master password is only held in memory; optional auto-unlock stores it
  AES-256-GCM encrypted on disk.
- Agent tokens: SHA-256 hashes in config; plaintext only in the encrypted
  `agent-tokens.json` (for copy/rotate) — or use environment variables instead.
- Admin page: password plus TOTP when TOTP is enabled. OIDC only for the bound subject. Login throttling. `HttpOnly` `SameSite=Strict` session cookie.
- Every read is authorized by an active grant or a not-yet-consumed `once` approval, then audited. Revoke and expiry apply to an old request id.
- ntfy approvals are one-time `POST` actions. A signed `GET` only shows a confirm form.
- This is a self-hosted tool: run it behind a private network or a tunnel/Access
  policy; do not expose port 8788 directly.

## Configuration

Main environment variables:

| Variable | Meaning |
|---|---|
| `SECRETS_BROKER_HOME` | data directory (default `~/.secrets-broker`) |
| `SECRETS_BROKER_PORT` / `SECRETS_BROKER_BIND` | listen port/address (default `127.0.0.1`; `0.0.0.0` in the image) |
| `SECRETS_BROKER_ADMIN_PASSWORD` | admin login password |
| `SECRETS_BROKER_BEHIND_PROXY` | set to `1` when a tunnel reaches a loopback bind |
| `BROKER_PUBLIC_URL` | public URL for approval actions and OAuth metadata |
| `SECRETS_BROKER_BW` | `bw` binary or path to `bw.js` |
| `SECRETS_BROKER_ENCRYPTION_KEY` / `SECRETS_BROKER_KEY_FILE` | 32-byte base64 key, or a key file outside the data directory |
| `SECRETS_BROKER_OAUTH` / `SECRETS_BROKER_OAUTH_REGISTRATION` | both off by default |
| `NTFY_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_USER_ID` | private ntfy topic and the bound Telegram owner |
| `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` | Cloudflare Access service token for the stdio adapter and `wh.mjs` |
| `MCP_ALLOW_READ` | expose `get_secret` over MCP; leave unset |

Most other settings (vault URL, OIDC, notification providers, public URL) can be
edited in the UI and are persisted to `config.json`.

## Documentation

- [Getting started](docs/getting-started.md)
- [Configuration](docs/configuration.md)
- [MCP](docs/mcp.md)
- [Notifications](docs/notifications.md)
- [Security](docs/security.md)

## Repository layout

```
server.mjs            broker + dashboard + HTTP/MCP/OAuth server
mcp-server.mjs        stdio MCP adapter
wh.mjs                CLI helper (get / run --var)
docker-compose.yml    one-command Docker deployment
deploy/Dockerfile     container image (includes @bitwarden/cli)
deploy/install.sh     interactive installer
deploy/.env.example
docs/                 English documentation
```

## License

MIT
