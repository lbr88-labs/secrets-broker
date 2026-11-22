# MCP

The broker exposes MCP (Model Context Protocol) in two forms.

## Streamable HTTP

```
https://<your-broker>/mcp
```

Two authentication modes are supported:

### OAuth 2.1 (off by default)

OAuth stays off until `SECRETS_BROKER_OAUTH=1` (or `config.oauthEnabled`).
Prefer a static agent token. When OAuth is on, dynamic registration also
requires `SECRETS_BROKER_OAUTH_REGISTRATION=1` and an admin session cookie on
`POST /oauth/register`. A new client can read nothing until an admin sets its
allow-list. Deleting the `oauth:<client_id>` agent revokes the client.

`/oauth/approve` asks for the admin password and, if TOTP is enabled, the
current code. An existing admin cookie is not accepted on its own.

Clients that implement MCP authorization then discover the broker:

1. request `/mcp` without a token → `401` with
   `WWW-Authenticate: Bearer resource_metadata=".../​.well-known/oauth-protected-resource"`;
2. read `/.well-known/oauth-protected-resource` and
   `/.well-known/oauth-authorization-server`;
3. register a client with `POST /oauth/register` from an admin session (dynamic registration is not anonymous);
4. open `/oauth/authorize` in a browser — the user logs in to the broker if needed
   and clicks **Allow**;
5. exchange the code at `POST /oauth/token` with PKCE S256;
6. call `/mcp` with `Authorization: Bearer <access token>`.

Access tokens are valid for 24 hours and map to an agent named
`oauth:<client_id>`. Reads still require an explicit grant/approval and are
audited.

### Bearer token

```
Authorization: Bearer <agent token>
```

Agent tokens are created in the UI (Agents). They are stored hashed; copy them
from the UI.

## Tools

| Tool | Description |
|---|---|
| `list_secrets` | lists readable item names (and URLs) |
| `create_secret` | create/update an item; requires write access for the agent |
| `request_access` | create a pending approval for an item |
| `get_secret` | optional; only when `MCP_ALLOW_READ=1`; returns plaintext |

`get_secret` returns the value to the calling model, so it is disabled by
default. Prefer `request_access` + a connector that reads the value outside the
model, or the stdio adapter's `exec_with_secrets`.

## stdio adapter

```json
{
  "mcpServers": {
    "secrets": {
      "command": "node",
      "args": ["/path/to/secrets-broker/mcp-server.mjs"],
      "env": {
        "BROKER_URL": "https://<your-broker>",
        "BROKER_AGENT_TOKEN": "<agent token>",
        "MCP_ALLOW_READ": "0"
      }
    }
  }
}
```

The stdio adapter additionally provides `exec_with_secrets`, which injects
secrets into a child process environment. The result masks the secret value and
its base64, base64url, URL-encoded and hex forms, including a value split across
writes. The command is started by a parent process whose environment does not
include `BROKER_AGENT_TOKEN`, `SECRETS_BROKER_TOKEN`, the Cloudflare Access
service token, or the admin, master and encryption-key variables, so
`/proc/$PPID/environ` does not contain them.

Masking does not stop a command that wants the value. A prefix, a reversed or
spaced string, or an encoding of the value with extra text is not removed. The
helper process above that parent still has the original environment, and the
token remains in the helper's memory and in the harness MCP config.

Add the Access service token next to the agent token when the broker is behind
Cloudflare Access:

```json
"CF_ACCESS_CLIENT_ID": "<access client id>",
"CF_ACCESS_CLIENT_SECRET": "<access client secret>"
```

`wh.mjs` reads the same two variables, plus `SECRETS_BROKER_URL` and
`SECRETS_BROKER_TOKEN`. Do not point `BROKER_AGENT` at a name and expect the
adapter to reuse `config.agents`: that field is a `sha256:` hash, and a hash is
never sent as a bearer token.
