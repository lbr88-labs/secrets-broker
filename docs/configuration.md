# Configuration

Settings can be supplied as environment variables or edited in the UI
(Settings → saved to `config.json`). UI values take precedence over environment
variables, so a self-hosted instance can be configured entirely in the browser.

## Core

| Variable | Default | Description |
|---|---|---|
| `SECRETS_BROKER_HOME` | `~/.secrets-broker` | data directory |
| `SECRETS_BROKER_PORT` | `8788` | listen port |
| `SECRETS_BROKER_BIND` | `127.0.0.1` | listen address. The image sets `0.0.0.0` so Docker can publish `127.0.0.1:8788:8788` |
| `SECRETS_BROKER_ADMIN_PASSWORD` | — | admin login password. Required when the bind is not loopback, when `SECRETS_BROKER_BEHIND_PROXY=1`, or when `BROKER_PUBLIC_URL` is not loopback |
| `SECRETS_BROKER_BEHIND_PROXY` | off | set to `1` if a tunnel reaches a loopback bind. A non-loopback public URL counts as behind a proxy |
| `BROKER_PUBLIC_URL` | `http://127.0.0.1:8788` | public URL used in ntfy action buttons and OAuth metadata. `https://` turns on the `Secure` admin cookie |
| `SECRETS_BROKER_COOKIE_SECURE` | automatic | `1` forces `Secure`; `0` forces it off. Otherwise `Secure` follows `BROKER_PUBLIC_URL` and `x-forwarded-proto` |
| `SECRETS_BROKER_ADMIN_SESSION_TTL_MS` | 12 hours | admin session lifetime |
| `SECRETS_BROKER_BW` | `bw` | `bw` binary or path to `bw.js` |
| `SECRETS_BROKER_ENCRYPTION_KEY` | generated file | 32-byte base64 AES-256-GCM key. Prefer this, or `SECRETS_BROKER_KEY_FILE` outside the data directory |
| `SECRETS_BROKER_MASTER_PASSWORD` | — | unlocks the vault at startup. The on-disk `master-password` file is ignored while the key lives in the data directory |
| `SECRETS_BROKER_OAUTH` | off | `1` enables the OAuth authorization server |
| `SECRETS_BROKER_OAUTH_REGISTRATION` | off | `1` allows dynamic registration, and only from an admin session |
| `SECRETS_BROKER_PENDING_TTL_MS` | 10 minutes | drop unanswered approval requests older than this |
| `MCP_ALLOW_READ` | unset | expose `get_secret` over MCP. Leave unset |
| `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` | — | sent by `mcp-server.mjs` and `wh.mjs` when both are set |

## Vault

| Variable | Description |
|---|---|
| `BW_SERVER` | Bitwarden-compatible server URL |
| `BW_CLIENTID` | personal API key client id |
| `BW_CLIENTSECRET` | personal API key client secret |

The container's entrypoint runs `bw config server` and `bw login --apikey` once;
the unlock session is only kept in memory.

## OIDC (admin login)

| Variable | Description |
|---|---|
| `OIDC_ISSUER` | issuer URL (any standard OIDC provider) |
| `OIDC_CLIENT_ID` | client id |
| `OIDC_CLIENT_SECRET` | optional client secret (public PKCE clients can omit it) |
| `OIDC_REDIRECT_URI` | defaults to `${BROKER_PUBLIC_URL}/oidc/callback` |

The provider must allow the redirect URI above. The broker uses discovery, PKCE
and ID-token verification against the provider's JWKS (ES256, matching `kid`,
`exp` required).

Leave OIDC unset unless you need it. Login succeeds only when the ID token
`sub` equals the subject already stored in the profile. Binding a subject
requires an admin session: open `/oidc/login?bind=1` while logged in with the
admin password. There is no automatic bind on the first login.

### Advanced OIDC

The OIDC section has a collapsible advanced panel:

- **Endpoint overrides**: authorization/token/userinfo/JWKS URLs. Leave empty to
  use the issuer's discovery document; fill them for providers without discovery.
- **Scope**: default `openid profile email`.
- **Claim mapping**: identifier (default `sub`), name (`name`), email (`email`),
  avatar (`picture`). On first OIDC login the mapped claims are stored in the
  local profile. The stored `oidcSub` is what later logins must match.

## Optional features

- Auto-unlock: `SECRETS_BROKER_MASTER_PASSWORD`. A `master-password` file is
  used only when the encryption key is not inside the data directory.
- `autoImport` defaults to true (the original author's local credential import).
  Set `"autoImport": false` in `config.json` before unlocking a shared vault.
- Notifications: `NTFY_URL` and `NTFY_TOKEN`, `GOTIFY_URL`/`GOTIFY_TOKEN`,
  `WXPUSH_URL`/`WXPUSH_TOKEN`, `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` /
  `TELEGRAM_USER_ID`.
- TOTP 2FA and profile fields are configured in the UI (Profile). The TOTP
  secret is encrypted in `config.json`. `/login` and `/oauth/approve` both
  require the password and the current code.
