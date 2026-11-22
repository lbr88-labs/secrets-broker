# Deployment

## Docker Compose

```bash
cp .env.example .env
# edit .env: BW_SERVER, BW_CLIENTID, BW_CLIENTSECRET,
#            SECRETS_BROKER_ADMIN_PASSWORD, BROKER_PUBLIC_URL
docker compose up -d --build
```

Compose publishes `127.0.0.1:8788:8788`. Inside the container the process binds
`0.0.0.0` and runs as uid 1000 (`USER node`). If `./data` was created as root,
`chown 1000:1000` it or the process cannot write its state.

Keep the encryption key out of `./data`. Set `SECRETS_BROKER_ENCRYPTION_KEY` or
`SECRETS_BROKER_KEY_FILE`. On-disk auto-unlock is refused while
`encryption.key` sits in the data directory.

Expose the broker only through a private network or a tunnel (Cloudflare Tunnel,
Tailscale, WireGuard). Put Cloudflare Access in front of the hostname, with a
bypass for `POST /approve/*` only. ntfy action buttons are POSTs from the ntfy
app and do not send an Access cookie; the one-time bearer token still gates
them. Keep `GET /approve/*` and every other path behind Access. Give each
harness its own Access service token (`CF_ACCESS_CLIENT_ID` /
`CF_ACCESS_CLIENT_SECRET` on the stdio adapter) plus its own agent token. Leave
OIDC, OAuth and `MCP_ALLOW_READ` off. Set `SECRETS_BROKER_BEHIND_PROXY=1` when
the tunnel connects to loopback; a non-loopback `BROKER_PUBLIC_URL` already
requires an admin password.

For ntfy, run your own server and ACL the topic: read for your user only, write
for the broker's `NTFY_TOKEN`. Anyone who can read the topic can see the
one-time approval tokens.

## Synology / NAS

1. Create a directory such as `/volume1/docker/secrets-broker` and copy this
   repository into it (the Compose build context is the repository root).
2. `cp deploy/.env.example deploy/.env` and fill in the values.
3. `docker compose -f deploy/docker-compose.yml up -d --build`.
4. Open `http://127.0.0.1:8788/` on the NAS, or reach it through a tunnel. The
   compose file does not publish the port on every interface. `chown 1000:1000`
   the data directory so the container user can write it.

Docker Engine 24+ and Compose v2 are required.

## Auto-unlock

Do not rely on `data/master-password` while the encryption key is in the same
directory. The process logs a refusal and leaves the vault locked. Set
`SECRETS_BROKER_MASTER_PASSWORD` for unattended unlock, or move the key to a
Docker secret (`SECRETS_BROKER_ENCRYPTION_KEY` or `SECRETS_BROKER_KEY_FILE`)
before using the file. Remove the file in the UI (Settings → delete auto-unlock
file) to go back to typing the master password.

## Reverse proxy / Tunnel

A minimal generic configuration:

- Admin UI: `https://broker.example.com` → `http://127.0.0.1:8788`
- Agent API/MCP: use the same host, protected by agent tokens/OAuth approvals, or
  a separate hostname if you want Cloudflare Access on the admin UI only.

Set `BROKER_PUBLIC_URL` to the externally visible URL. ntfy action buttons and
OAuth metadata use it. An `https://` value sets the `Secure` flag on the admin
cookie. A hostname that is not loopback is treated as a proxy: the process
exits unless `SECRETS_BROKER_ADMIN_PASSWORD` is set.
