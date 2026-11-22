# Security

## Model

- **Vault**: secrets live in a Bitwarden-compatible vault (NodeWarden,
  Vaultwarden, Bitwarden). The broker uses the official `bw` CLI; the decrypted
  session lives in memory only.
- **Agents**: every agent has its own token. The token is stored as a SHA-256 hash
  in `config.json`; plaintext is kept only in the encrypted `agent-tokens.json`
  for copy/rotate, or can be supplied through `SECRETS_BROKER_TOKEN`.
- **Approval**: a read requires either an active grant or an explicit approval
  (once / 1h / 24h / 7d / permanent). Grants can have a read-count limit and an
  expiry; every read is audited.
- **Human channels**: web UI, Telegram buttons from the configured user, and ntfy
  `http` POST actions (a signed GET only shows a confirm form). Gotify and
  wxpush receive the same text and do not get a capability URL. OAuth consent
  is off unless `SECRETS_BROKER_OAUTH=1`.
- **Admin**: password, plus TOTP when it is enabled. OIDC is limited to the
  bound subject. Login throttling. Each login gets its own `HttpOnly`
  `SameSite=Strict` cookie, deleted on logout. `Secure` is set for an `https`
  public URL.

## Encryption at rest

`encryption.key` (32 bytes, mode 600) is generated on first start and used with
AES-256-GCM for:

- the auto-unlock master password (`master-password`),
- the OIDC client secret and the TOTP secret,
- Telegram / Gotify / wxpush tokens and the ntfy access token,
- plaintext agent tokens (`agent-tokens.json`).

Keep that key off the data volume. Set `SECRETS_BROKER_ENCRYPTION_KEY` (32-byte
base64) or `SECRETS_BROKER_KEY_FILE` to a Docker secret or a path outside
`SECRETS_BROKER_HOME`. While the key file sits in the data directory, the
broker refuses to read `master-password` and logs that refusal.

The data directory is created mode `0700`. `config.json`, `grants.json`,
`audit.log`, `agent-tokens.json` and the key file are mode `0600`.

Back up the key together with `data/`. Losing it makes these fields
unrecoverable (agent tokens themselves remain valid for the agents that hold
them).

## Auto-unlock trade-off

Prefer `SECRETS_BROKER_MASTER_PASSWORD` for a restart, or type the master
password in the UI. The on-disk `master-password` file is not read when
`encryption.key` is inside the data directory, because anyone who can read the
volume could decrypt it. It is used only when the key comes from the environment
or from a key file outside that directory. Delete the file (Settings → delete
auto-unlock file) to go back to manual unlock.

## Deployment checklist

See the README section **Secure deployment**. In short:

- Publish `127.0.0.1:8788` only, or reach the broker through a tunnel. Set
  `SECRETS_BROKER_BEHIND_PROXY=1` when the tunnel arrives on localhost.
- Set a strong `SECRETS_BROKER_ADMIN_PASSWORD`. Leave OIDC and OAuth off.
- Leave `MCP_ALLOW_READ` unset. Set `autoImport` to `false`.
- Put the encryption key outside the data volume. Do not enable on-disk
  auto-unlock.
- One Cloudflare Access service token per harness, and keep `/approve/` behind
  Access. Use a private ntfy topic with `NTFY_TOKEN`.
- Give each agent an allow-list. An empty list grants nothing.
- The container runs as uid 1000. `chown 1000:1000` the data directory if it
  was created as root.
- Rotate agent tokens when a machine is retired (UI → Agents → rotate).
- Review the audit log after connecting a new agent.
