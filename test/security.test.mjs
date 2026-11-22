import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtemp, rm, readFile, writeFile, stat, chmod } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import http from 'node:http'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { createRedactor, redactSecrets } from '../redact.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const SERVER = path.join(ROOT, 'server.mjs')
const FAKE_BW = path.join(ROOT, 'test', 'fake-bw.js')
const TOTP_SECRET = 'JBSWY3DPEHPK3PXP'

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function modeOf(value) {
  return value.mode & 0o777
}

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
function base32Decode(text) {
  let bits = 0
  let value = 0
  const out = []
  for (const char of String(text).toUpperCase().replace(/=+$/, '')) {
    const index = BASE32.indexOf(char)
    if (index < 0) continue
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Buffer.from(out)
}
function totpCode(secret, offset = 0) {
  const counter = Math.floor(Date.now() / 30000) + offset
  const buffer = Buffer.alloc(8)
  buffer.writeUInt32BE(Math.floor(counter / 2 ** 32), 0)
  buffer.writeUInt32BE(counter >>> 0, 4)
  const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(buffer).digest()
  const dynamic = hmac[hmac.length - 1] & 0x0f
  const code = (((hmac[dynamic] & 0x7f) << 24) | (hmac[dynamic + 1] << 16) | (hmac[dynamic + 2] << 8) | hmac[dynamic + 3]) % 1e6
  return String(code).padStart(6, '0')
}

async function freePort() {
  return await new Promise((resolve, reject) => {
    const server = http.createServer()
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      server.close((error) => (error ? reject(error) : resolve(port)))
    })
  })
}

function cookieHeader(response) {
  const list = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : []
  return list.map((part) => part.split(';')[0]).join('; ')
}

function cleanEnv(extra = {}) {
  const env = { ...process.env, ...extra }
  for (const key of [
    'SECRETS_BROKER_MOCK',
    'TELEGRAM_BOT_TOKEN',
    'TELEGRAM_CHAT_ID',
    'TELEGRAM_USER_ID',
    'OIDC_ISSUER',
    'OIDC_CLIENT_ID',
    'OIDC_CLIENT_SECRET',
    'NTFY_URL',
    'NTFY_TOKEN',
    'MCP_ALLOW_READ',
    'SECRETS_BROKER_OAUTH',
    'SECRETS_BROKER_OAUTH_REGISTRATION',
    'SECRETS_BROKER_BEHIND_PROXY',
    'SECRETS_BROKER_ENCRYPTION_KEY',
    'SECRETS_BROKER_KEY_FILE',
    'CF_ACCESS_CLIENT_ID',
    'CF_ACCESS_CLIENT_SECRET',
  ]) {
    if (!(key in extra)) delete env[key]
  }
  return env
}

async function startBroker(extra = {}, { config, files = {}, masterPassword = 'vault-master', password = 'test-admin-password' } = {}) {
  const home = await mkdtemp(path.join(tmpdir(), 'broker-'))
  await chmod(home, 0o700)
  if (config !== undefined) {
    await writeFile(path.join(home, 'config.json'), JSON.stringify(config, null, 2), { mode: 0o644 })
  }
  for (const [name, contents] of Object.entries(files)) {
    await writeFile(path.join(home, name), contents, { mode: 0o600 })
  }
  const port = extra.SECRETS_BROKER_PORT ?? (await freePort())
  const env = cleanEnv({
    SECRETS_BROKER_HOME: home,
    SECRETS_BROKER_PORT: String(port),
    SECRETS_BROKER_BIND: '127.0.0.1',
    SECRETS_BROKER_BW: FAKE_BW,
    SECRETS_BROKER_ADMIN_PASSWORD: password,
    SECRETS_BROKER_MASTER_PASSWORD: masterPassword,
    BROKER_PUBLIC_URL: `http://127.0.0.1:${port}`,
    SECRETS_BROKER_COOKIE_SECURE: '0',
    ...extra,
  })
  const child = spawn(process.execPath, [SERVER], { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] })
  let logs = ''
  child.stdout.on('data', (chunk) => {
    logs += chunk
  })
  child.stderr.on('data', (chunk) => {
    logs += chunk
  })
  const base = `http://127.0.0.1:${port}`
  const ready = (async () => {
    const deadline = Date.now() + 8000
    while (Date.now() < deadline) {
      if (child.exitCode !== null) throw new Error(`broker exited ${child.exitCode}\n${logs}`)
      if (logs.includes('listening')) return
      await sleep(30)
    }
    throw new Error(`broker did not listen\n${logs}`)
  })()
  ready.catch(() => {})
  return {
    home,
    port: Number(port),
    base,
    child,
    logs: () => logs,
    env,
    ready,
    async stop() {
      if (child.exitCode === null) {
        child.kill('SIGTERM')
        await Promise.race([new Promise((resolve) => child.once('exit', resolve)), sleep(2000)])
        if (child.exitCode === null) child.kill('SIGKILL')
      }
      await rm(home, { recursive: true, force: true })
    },
  }
}

async function login(base, password = 'test-admin-password', code = '') {
  const body = new URLSearchParams({ password })
  if (code) body.set('code', code)
  const response = await fetch(`${base}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
    redirect: 'manual',
  })
  return { response, cookie: cookieHeader(response) }
}

async function waitUnlocked(base, cookie) {
  for (let attempt = 0; attempt < 40; attempt++) {
    const response = await fetch(`${base}/api/status`, { headers: { cookie } })
    if (response.status === 200) {
      const body = await response.json()
      if (body.unlocked) return body
    }
    await sleep(50)
  }
  throw new Error('vault did not auto-unlock')
}

async function adminPost(base, cookie, pathname, fields) {
  const response = await fetch(`${base}${pathname}`, {
    method: 'POST',
    redirect: 'manual',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded', 'x-broker-json': '1' },
    body: new URLSearchParams(fields),
  })
  const payload = await response.json().catch(() => ({}))
  return { status: response.status, payload }
}

async function provisionAgent(broker, { name = 'bot', allow = 'gatewayapi', write = false, grant = null } = {}) {
  await broker.ready
  const session = await login(broker.base)
  assert.equal(session.response.status, 303, 'admin login should succeed')
  await waitUnlocked(broker.base, session.cookie)
  const added = await adminPost(broker.base, session.cookie, '/api/agents/add', { name })
  assert.equal(added.status, 200, JSON.stringify(added.payload))
  if (allow !== null) {
    const access = await adminPost(broker.base, session.cookie, '/api/agents/access', { name, allow })
    assert.equal(access.status, 200, JSON.stringify(access.payload))
  }
  if (write) {
    const flag = await adminPost(broker.base, session.cookie, '/api/agents/write', { name, allow: '1' })
    assert.equal(flag.status, 200, JSON.stringify(flag.payload))
  }
  if (grant) {
    const created = await adminPost(broker.base, session.cookie, '/api/grants/create', {
      agent: name,
      name: grant.item,
      ttlHours: String(grant.ttlHours ?? 1),
      maxReads: String(grant.maxReads ?? 0),
    })
    assert.equal(created.status, 200, JSON.stringify(created.payload))
  }
  return { cookie: session.cookie, token: added.payload.token, name }
}

async function expectExit(extra) {
  const broker = await startBroker(extra, { masterPassword: '', password: '' })
  const exit = await Promise.race([
    new Promise((resolve) => broker.child.once('exit', resolve)),
    sleep(4000).then(() => 'timeout'),
  ])
  const logs = broker.logs()
  await broker.stop()
  return { exit, logs }
}

test('refuses to start on a non-loopback bind without an admin password', async () => {
  const { exit, logs } = await expectExit({ SECRETS_BROKER_BIND: '0.0.0.0', SECRETS_BROKER_ADMIN_PASSWORD: '' })
  assert.equal(exit, 1)
  assert.match(logs, /admin password/i)
})

test('refuses to start behind a proxy without an admin password', async () => {
  const { exit, logs } = await expectExit({
    SECRETS_BROKER_BIND: '127.0.0.1',
    SECRETS_BROKER_BEHIND_PROXY: '1',
    SECRETS_BROKER_ADMIN_PASSWORD: '',
  })
  assert.equal(exit, 1)
  assert.match(logs, /admin password/i)
})

test('a loopback request is not admin when no password is set', async () => {
  const broker = await startBroker(
    { SECRETS_BROKER_ADMIN_PASSWORD: '', SECRETS_BROKER_MASTER_PASSWORD: '' },
    { password: '', masterPassword: '' },
  )
  try {
    await broker.ready
    const response = await fetch(`${broker.base}/api/agents`)
    const text = await response.text()
    assert.equal(response.status === 200 && text.includes('"agents"'), false)
    assert.match(text, /ADMIN_PASSWORD|登录|password/i)
  } finally {
    await broker.stop()
  }
})

test('fresh install creates no default agents and private data files', async () => {
  const broker = await startBroker()
  try {
    await broker.ready
    const config = JSON.parse(await readFile(path.join(broker.home, 'config.json'), 'utf8'))
    assert.deepEqual(config.agents ?? {}, {})
    assert.equal(config.agents?.dsh, undefined)
    assert.equal(config.agents?.codex, undefined)
    assert.equal(config.agents?.hermes, undefined)
    assert.equal(config.autoImport, false)
    const dir = await stat(broker.home)
    const file = await stat(path.join(broker.home, 'config.json'))
    assert.equal(modeOf(dir), 0o700)
    assert.equal(modeOf(file), 0o600)
    const session = await login(broker.base)
    await waitUnlocked(broker.base, session.cookie)
    const audit = await stat(path.join(broker.home, 'audit.log'))
    assert.equal(modeOf(audit), 0o600)
  } finally {
    await broker.stop()
  }
})

test('on-disk auto-unlock stays off while the encryption key sits in the data directory', async () => {
  const broker = await startBroker(
    { SECRETS_BROKER_MASTER_PASSWORD: '' },
    { masterPassword: '', password: 'test-admin-password', files: { 'master-password': 'vault-master\n' } },
  )
  try {
    await broker.ready
    const session = await login(broker.base)
    const response = await fetch(`${broker.base}/api/status`, { headers: { cookie: session.cookie } })
    const body = await response.json()
    assert.equal(body.unlocked, false)
    assert.match(broker.logs(), /refusing on-disk auto-unlock/i)
  } finally {
    await broker.stop()
  }
})

test('admin cookie is random, expires, and dies on logout', async () => {
  const broker = await startBroker({ SECRETS_BROKER_ADMIN_SESSION_TTL_MS: '400' })
  try {
    await broker.ready
    const first = await login(broker.base)
    const second = await login(broker.base)
    assert.notEqual(first.cookie, second.cookie)
    assert.match(first.response.headers.get('set-cookie') ?? '', /HttpOnly/i)
    assert.match(first.response.headers.get('set-cookie') ?? '', /SameSite=Strict/i)
    const ok = await fetch(`${broker.base}/api/status`, { headers: { cookie: first.cookie } })
    assert.equal(ok.status, 200)
    const logout = await fetch(`${broker.base}/api/logout`, {
      method: 'POST',
      headers: { cookie: first.cookie, 'x-broker-json': '1' },
    })
    assert.equal(logout.status, 200)
    const after = await fetch(`${broker.base}/api/status`, { headers: { cookie: first.cookie } })
    const afterText = await after.text()
    assert.equal(afterText.includes('"unlocked"'), false)
    const still = await fetch(`${broker.base}/api/status`, { headers: { cookie: second.cookie } })
    assert.equal(still.status, 200)
    await sleep(500)
    const expired = await fetch(`${broker.base}/api/status`, { headers: { cookie: second.cookie } })
    assert.equal((await expired.text()).includes('"unlocked"'), false)
  } finally {
    await broker.stop()
  }
})

test('https public URL sets a Secure admin cookie', async () => {
  const broker = await startBroker({
    BROKER_PUBLIC_URL: 'https://broker.example.test',
    SECRETS_BROKER_COOKIE_SECURE: '',
  })
  try {
    await broker.ready
    const session = await login(broker.base)
    const header = session.response.headers.get('set-cookie') ?? ''
    assert.match(header, /Secure/i)
    assert.match(header, /HttpOnly/i)
    assert.match(header, /SameSite=Strict/i)
  } finally {
    await broker.stop()
  }
})

test('read after revoke or expiry does not return the secret', async () => {
  const broker = await startBroker()
  try {
    const agent = await provisionAgent(broker, { allow: 'gatewayapi' })
    const pending = await fetch(`${broker.base}/secret?name=gatewayapi`, {
      headers: { authorization: `Bearer ${agent.token}` },
    })
    assert.equal(pending.status, 202)
    const { requestId } = await pending.json()
    const decision = await adminPost(broker.base, agent.cookie, `/api/requests/${requestId}/decide`, { decision: '1h' })
    assert.equal(decision.status, 303)
    const first = await fetch(`${broker.base}/secret/pending/${requestId}`, {
      headers: { authorization: `Bearer ${agent.token}` },
    })
    assert.equal(first.status, 200)
    assert.equal((await first.json()).value, 'GW-SECRET-1234')
    const revoked = await adminPost(broker.base, agent.cookie, '/api/grants/revoke', { agent: 'bot', name: 'gatewayapi' })
    assert.equal(revoked.status, 200)
    const after = await fetch(`${broker.base}/secret/pending/${requestId}`, {
      headers: { authorization: `Bearer ${agent.token}` },
    })
    const afterBody = await after.json()
    assert.notEqual(after.status, 200)
    assert.notEqual(afterBody.value, 'GW-SECRET-1234')
    const again = await fetch(`${broker.base}/secret?name=gatewayapi`, {
      headers: { authorization: `Bearer ${agent.token}` },
    })
    assert.equal(again.status, 202)
  } finally {
    await broker.stop()
  }
})

test('an expired grant is not readable through the old request id', async () => {
  const broker = await startBroker()
  try {
    const agent = await provisionAgent(broker, { allow: 'gatewayapi' })
    const pending = await fetch(`${broker.base}/secret?name=gatewayapi`, {
      headers: { authorization: `Bearer ${agent.token}` },
    })
    const { requestId } = await pending.json()
    await adminPost(broker.base, agent.cookie, `/api/requests/${requestId}/decide`, { decision: '1h' })
    await adminPost(broker.base, agent.cookie, '/api/grants/set-expiry', {
      agent: 'bot',
      name: 'gatewayapi',
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    })
    const after = await fetch(`${broker.base}/secret/pending/${requestId}`, {
      headers: { authorization: `Bearer ${agent.token}` },
    })
    const body = await after.json()
    assert.notEqual(body.value, 'GW-SECRET-1234')
  } finally {
    await broker.stop()
  }
})

test('old pending requests expire', async () => {
  const broker = await startBroker({ SECRETS_BROKER_PENDING_TTL_MS: '200' })
  try {
    const agent = await provisionAgent(broker, { allow: 'gatewayapi' })
    const pending = await fetch(`${broker.base}/secret?name=gatewayapi`, {
      headers: { authorization: `Bearer ${agent.token}` },
    })
    const { requestId } = await pending.json()
    await sleep(350)
    const listed = await fetch(`${broker.base}/api/pending`, { headers: { cookie: agent.cookie } })
    const body = await listed.json()
    assert.equal((body.requests ?? []).some((entry) => entry.id === requestId), false)
  } finally {
    await broker.stop()
  }
})

test('parallel reads cannot exceed maxReads or reuse a once approval', async () => {
  const broker = await startBroker({ FAKE_BW_DELAY_MS: '350' })
  try {
    const agent = await provisionAgent(broker, { allow: 'gatewayapi', grant: { item: 'gatewayapi', ttlHours: 1, maxReads: 1 } })
    const reads = await Promise.all(
      Array.from({ length: 8 }, () =>
        fetch(`${broker.base}/secret?name=gatewayapi`, { headers: { authorization: `Bearer ${agent.token}` } }).then(async (response) => ({
          status: response.status,
          body: await response.json(),
        })),
      ),
    )
    const values = reads.filter((result) => result.body.value === 'GW-SECRET-1234')
    assert.equal(values.length, 1, JSON.stringify(reads.map((result) => result.status)))

    const onceAgent = await provisionAgent(broker, { name: 'oncebot', allow: 'gatewayapi' })
    const pending = await fetch(`${broker.base}/secret?name=gatewayapi`, {
      headers: { authorization: `Bearer ${onceAgent.token}` },
    })
    const { requestId } = await pending.json()
    await adminPost(broker.base, onceAgent.cookie, `/api/requests/${requestId}/decide`, { decision: 'once' })
    const polls = await Promise.all(
      Array.from({ length: 6 }, () =>
        fetch(`${broker.base}/secret/pending/${requestId}`, { headers: { authorization: `Bearer ${onceAgent.token}` } }).then(async (response) => ({
          status: response.status,
          body: await response.json().catch(() => ({})),
        })),
      ),
    )
    assert.equal(polls.filter((result) => result.body.value === 'GW-SECRET-1234').length, 1)
  } finally {
    await broker.stop()
  }
})

test('oauth stays off by default and TOTP alone cannot mint a code', async () => {
  const closed = await startBroker()
  try {
    await closed.ready
    const register = await fetch(`${closed.base}/oauth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['https://attacker.example/cb'], client_name: 'evil' }),
    })
    assert.notEqual(register.status, 201)
    const approve = await fetch(`${closed.base}/oauth/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ decision: 'allow', client_id: 'x', redirect_uri: 'https://attacker.example/cb' }),
      redirect: 'manual',
    })
    const location = approve.headers.get('location') ?? ''
    assert.equal(location.includes('code='), false)
  } finally {
    await closed.stop()
  }

  const broker = await startBroker(
    { SECRETS_BROKER_OAUTH: '1' },
    {
      config: {
        port: 8788,
        serverUrl: 'https://vault.example.com',
        bwJs: FAKE_BW,
        autoImport: false,
        agents: {},
        oauthEnabled: true,
        profile: { totpEnabled: true, totpSecret: TOTP_SECRET },
      },
    },
  )
  try {
    await broker.ready
    const session = await login(broker.base, 'test-admin-password', totpCode(TOTP_SECRET))
    assert.equal(session.response.status, 303)
    const open = await fetch(`${broker.base}/oauth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['https://attacker.example/cb'], client_name: 'evil' }),
    })
    assert.equal(open.status, 403)
    const registered = await fetch(`${broker.base}/oauth/register`, {
      method: 'POST',
      headers: { cookie: session.cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['https://attacker.example/cb'], client_name: 'evil' }),
    })
    assert.equal(registered.status, 403)

    broker.child.kill('SIGTERM')
  } finally {
    await broker.stop()
  }

  const opened = await startBroker(
    { SECRETS_BROKER_OAUTH: '1', SECRETS_BROKER_OAUTH_REGISTRATION: '1' },
    {
      config: {
        port: 8788,
        serverUrl: 'https://vault.example.com',
        bwJs: FAKE_BW,
        autoImport: false,
        agents: {},
        profile: { totpEnabled: true, totpSecret: TOTP_SECRET },
      },
    },
  )
  try {
    await opened.ready
    const anonymous = await fetch(`${opened.base}/oauth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['https://attacker.example/cb'] }),
    })
    assert.equal(anonymous.status, 403)
    const session = await login(opened.base, 'test-admin-password', totpCode(TOTP_SECRET))
    const registered = await fetch(`${opened.base}/oauth/register`, {
      method: 'POST',
      headers: { cookie: session.cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['https://app.example/callback'], client_name: 'harness' }),
    })
    assert.equal(registered.status, 201)
    const client = await registered.json()
    const verifier = crypto.randomBytes(32).toString('base64url')
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url')
    const fields = {
      client_id: client.client_id,
      redirect_uri: 'https://app.example/callback',
      response_type: 'code',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: 'st',
      decision: 'allow',
    }
    const totpOnly = await fetch(`${opened.base}/oauth/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: session.cookie },
      body: new URLSearchParams({ ...fields, code: totpCode(TOTP_SECRET) }),
      redirect: 'manual',
    })
    assert.equal((totpOnly.headers.get('location') ?? '').includes('code='), false)
    const approved = await fetch(`${opened.base}/oauth/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ ...fields, password: 'test-admin-password', code: totpCode(TOTP_SECRET) }),
      redirect: 'manual',
    })
    const location = approved.headers.get('location') ?? ''
    assert.equal(approved.status, 302)
    const code = new URL(location).searchParams.get('code')
    assert.ok(code)
    const tokenResponse = await fetch(`${opened.base}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: client.client_id,
        redirect_uri: 'https://app.example/callback',
        code_verifier: verifier,
      }),
    })
    assert.equal(tokenResponse.status, 200)
    const token = (await tokenResponse.json()).access_token
    await waitUnlocked(opened.base, session.cookie)
    const items = await fetch(`${opened.base}/agent/items`, { headers: { authorization: `Bearer ${token}` } })
    const listed = await items.json()
    assert.equal(items.status, 200)
    assert.deepEqual(listed.items ?? [], [])
    const agentName = `oauth:${client.client_id}`
    const access = await adminPost(opened.base, session.cookie, '/api/agents/access', { name: agentName, allow: 'gatewayapi' })
    assert.equal(access.status, 200, JSON.stringify(access.payload))
    const scoped = await fetch(`${opened.base}/agent/items`, { headers: { authorization: `Bearer ${token}` } })
    const scopedBody = await scoped.json()
    assert.deepEqual(scopedBody.items.map((item) => item.name), ['gatewayapi'])
    let sawThrottle = false
    for (let attempt = 0; attempt < 8; attempt++) {
      const response = await fetch(`${opened.base}/oauth/approve`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ ...fields, code: totpCode(TOTP_SECRET), password: 'wrong-password' }),
        redirect: 'manual',
      })
      assert.equal((response.headers.get('location') ?? '').includes('code='), false)
      if (response.status === 429) sawThrottle = true
    }
    assert.equal(sawThrottle, true)
    const afterOauthLock = await login(opened.base, 'test-admin-password', totpCode(TOTP_SECRET))
    assert.equal(afterOauthLock.response.status, 303)
    const removed = await adminPost(opened.base, session.cookie, '/api/agents/delete', { name: agentName })
    assert.equal(removed.status, 200, JSON.stringify(removed.payload))
    const revoked = await fetch(`${opened.base}/agent/items`, { headers: { authorization: `Bearer ${token}` } })
    assert.equal(revoked.status, 401)
  } finally {
    await opened.stop()
  }
})

test('an unauthenticated oauth approve does not issue a code when no admin password is set', async () => {
  const broker = await startBroker(
    { SECRETS_BROKER_OAUTH: '1', SECRETS_BROKER_ADMIN_PASSWORD: '', SECRETS_BROKER_MASTER_PASSWORD: '' },
    { password: '', masterPassword: '' },
  )
  try {
    await broker.ready
    const response = await fetch(`${broker.base}/oauth/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        decision: 'allow',
        client_id: 'mcp_attacker',
        redirect_uri: 'https://attacker.example/cb',
        code_challenge: 'abc',
        code_challenge_method: 'S256',
      }),
      redirect: 'manual',
    })
    assert.equal((response.headers.get('location') ?? '').includes('code='), false)
  } finally {
    await broker.stop()
  }
})

test('empty allow-list reads nothing and writes cannot leave the allow-list', async () => {
  const broker = await startBroker()
  try {
    const agent = await provisionAgent(broker, { allow: '', write: true })
    const items = await fetch(`${broker.base}/agent/items`, { headers: { authorization: `Bearer ${agent.token}` } })
    assert.deepEqual((await items.json()).items, [])
    const secret = await fetch(`${broker.base}/secret?name=gatewayapi`, { headers: { authorization: `Bearer ${agent.token}` } })
    assert.equal(secret.status, 403)
    const overwrite = await fetch(`${broker.base}/agent/items/save`, {
      method: 'POST',
      headers: { authorization: `Bearer ${agent.token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'other-key', value: 'pwned' }),
    })
    assert.equal(overwrite.status, 403)
    const created = await fetch(`${broker.base}/agent/items/save`, {
      method: 'POST',
      headers: { authorization: `Bearer ${agent.token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'brand-new', value: 'pwned' }),
    })
    assert.equal(created.status, 403)
    await adminPost(broker.base, agent.cookie, '/api/agents/access', { name: 'bot', allow: 'gatewayapi' })
    const allowed = await fetch(`${broker.base}/agent/items/save`, {
      method: 'POST',
      headers: { authorization: `Bearer ${agent.token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'gatewayapi', value: 'updated-value' }),
    })
    assert.equal(allowed.status, 200, await allowed.text())
    const stillBlocked = await fetch(`${broker.base}/agent/items/save`, {
      method: 'POST',
      headers: { authorization: `Bearer ${agent.token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'other-key', value: 'pwned' }),
    })
    assert.equal(stillBlocked.status, 403)
  } finally {
    await broker.stop()
  }
})

test('telegram messages cannot rebind the owner and foreign callbacks are ignored', async () => {
  const api = await listen((req, res) => {
    api.hits += 1
    let body = ''
    req.on('data', (chunk) => {
      body += chunk
    })
    req.on('end', () => {
      const payload = body ? JSON.parse(body) : {}
      if (req.url.endsWith('/getUpdates')) {
        const batch = api.updates.splice(0)
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ ok: true, result: batch }))
        return
      }
      api.calls.push({ url: req.url, payload })
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, result: {} }))
    })
  })
  api.hits = 0
  api.updates = []
  api.calls = []
  const broker = await startBroker({
    SECRETS_BROKER_TELEGRAM_API: api.base,
    SECRETS_BROKER_TELEGRAM_POLL_MS: '80',
    TELEGRAM_BOT_TOKEN: 'test-token',
    TELEGRAM_CHAT_ID: '111',
    TELEGRAM_USER_ID: '222',
  })
  try {
    await broker.ready
    api.updates.push({
      update_id: 1,
      message: { message_id: 1, chat: { id: 999 }, from: { id: 999 }, text: '/start' },
    })
    await waitFor(() => api.hits > 0 && api.updates.length === 0)
    const config = JSON.parse(await readFile(path.join(broker.home, 'config.json'), 'utf8'))
    assert.notEqual(String(config.telegram?.chatId ?? ''), '999')
    const sentToAttacker = api.calls.some((call) => String(call.payload.chat_id) === '999')
    assert.equal(sentToAttacker, false)

    const agent = await provisionAgent(broker, { allow: 'gatewayapi' })
    const pending = await fetch(`${broker.base}/secret?name=gatewayapi`, {
      headers: { authorization: `Bearer ${agent.token}` },
    })
    const { requestId } = await pending.json()
    api.updates.push({
      update_id: 2,
      callback_query: {
        id: 'cb-evil',
        from: { id: 999 },
        message: { message_id: 5, chat: { id: 999 } },
        data: `apr:${requestId}:always`,
      },
    })
    await waitFor(() => api.updates.length === 0)
    await sleep(50)
    const still = await fetch(`${broker.base}/api/pending`, { headers: { cookie: agent.cookie } })
    const pendingBody = await still.json()
    assert.equal(pendingBody.requests.some((entry) => entry.id === requestId), true)

    api.updates.push({
      update_id: 3,
      callback_query: {
        id: 'cb-owner',
        from: { id: 222 },
        message: { message_id: 6, chat: { id: 111 } },
        data: `apr:${requestId}:once`,
      },
    })
    await waitFor(() => api.updates.length === 0)
    await sleep(80)
    const owned = await fetch(`${broker.base}/secret/pending/${requestId}`, {
      headers: { authorization: `Bearer ${agent.token}` },
    })
    assert.equal(owned.status, 200)
    assert.equal((await owned.json()).value, 'GW-SECRET-1234')
  } finally {
    await broker.stop()
    await api.close()
  }
})

test('ntfy uses a private token, action buttons, and a POST confirm step', async () => {
  const ntfy = await listen((req, res) => {
    let body = ''
    req.on('data', (chunk) => {
      body += chunk
    })
    req.on('end', () => {
      ntfy.requests.push({
        headers: req.headers,
        body,
      })
      res.writeHead(200)
      res.end('ok')
    })
  })
  ntfy.requests = []
  const broker = await startBroker({
    NTFY_URL: `${ntfy.base}/secrets`,
    NTFY_TOKEN: 'ntfy-private-token',
  })
  try {
    const agent = await provisionAgent(broker, { allow: 'gatewayapi' })
    const reason = `please approve ${'A'.repeat(400)} https://evil.example/phish \u202E`
    const pending = await fetch(
      `${broker.base}/secret?name=gatewayapi&command=${encodeURIComponent('printenv AWS')}&reason=${encodeURIComponent(reason)}`,
      { headers: { authorization: `Bearer ${agent.token}` } },
    )
    assert.equal(pending.status, 202)
    const { requestId } = await pending.json()
    await waitFor(() => ntfy.requests.length > 0)
    const note = ntfy.requests[0]
    assert.equal(note.headers.authorization, 'Bearer ntfy-private-token')
    assert.equal(note.body.includes('/approve/'), false)
    assert.equal(note.body.includes('https://evil.example/phish'), false)
    assert.match(note.body, /bot/i)
    assert.match(note.body, /gatewayapi/)
    const untrustedAt = note.body.search(/Untrusted text from the bot/i)
    assert.ok(untrustedAt > 0, note.body)
    assert.equal(note.body.slice(0, untrustedAt).includes('printenv AWS'), false, note.body)
    assert.equal(note.body.slice(untrustedAt).includes('printenv AWS'), true, note.body)
    assert.match(note.body, /untrusted|未验证|reason/i)
    const actions = JSON.parse(note.headers.actions ?? note.headers['x-actions'] ?? '[]')
    assert.ok(actions.length >= 1)
    assert.equal(actions.every((action) => action.action === 'http' && String(action.method).toUpperCase() === 'POST'), true)
    const once = actions.find((action) => /once/i.test(action.label))
    assert.ok(once)
    const token = String(once.headers?.Authorization ?? once.headers?.authorization ?? '').replace(/^Bearer /, '')
    assert.ok(token)
    const peek = await fetch(once.url)
    assert.equal(peek.status === 200 || peek.status === 400 || peek.status === 405, true)
    const still = await fetch(`${broker.base}/api/pending`, { headers: { cookie: agent.cookie } })
    assert.equal((await still.json()).requests.some((entry) => entry.id === requestId), true)
    const confirm = await fetch(once.url, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: once.body ?? '',
    })
    assert.equal(confirm.status, 200)
    const replay = await fetch(once.url, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
    })
    const replayText = await replay.text()
    assert.equal(replayText.includes('已批准') && replayText.includes('once') && replay.status === 200 && replayText.includes('已处理'), false)
    const read = await fetch(`${broker.base}/secret/pending/${requestId}`, {
      headers: { authorization: `Bearer ${agent.token}` },
    })
    assert.equal(read.status, 200)
    assert.equal((await read.json()).value, 'GW-SECRET-1234')
  } finally {
    await broker.stop()
    await ntfy.close()
  }
})

test('only the bound OIDC subject can log in and binding requires an admin session', async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const jwk = publicKey.export({ format: 'jwk' })
  jwk.kid = 'test-key'
  jwk.alg = 'ES256'
  jwk.use = 'sig'
  const codes = new Map()
  const idp = await listen((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1')
    if (url.pathname === '/.well-known/openid-configuration') {
      const metadata = {
        issuer: idp.base,
        authorization_endpoint: `${idp.base}/authorize`,
        token_endpoint: `${idp.base}/token`,
        jwks_uri: `${idp.base}/jwks`,
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(metadata))
      return
    }
    if (url.pathname === '/jwks') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ keys: [jwk] }))
      return
    }
    if (url.pathname === '/token') {
      let body = ''
      req.on('data', (chunk) => {
        body += chunk
      })
      req.on('end', () => {
        const params = new URLSearchParams(body)
        const token = codes.get(params.get('code'))
        res.writeHead(token ? 200 : 400, { 'content-type': 'application/json' })
        res.end(JSON.stringify(token ? { id_token: token } : { error: 'invalid_grant' }))
      })
      return
    }
    res.writeHead(404)
    res.end()
  })
  function sign(payload) {
    const header = Buffer.from(JSON.stringify({ alg: 'ES256', kid: 'test-key' })).toString('base64url')
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const signature = crypto.sign('sha256', Buffer.from(`${header}.${body}`), { key: privateKey, dsaEncoding: 'ieee-p1363' })
    return `${header}.${body}.${signature.toString('base64url')}`
  }
  const broker = await startBroker(
    {
      OIDC_ISSUER: idp.base,
      OIDC_CLIENT_ID: 'broker',
      OIDC_CLIENT_SECRET: 'oidc-secret',
    },
    {
      config: {
        port: 8788,
        serverUrl: 'https://vault.example.com',
        bwJs: FAKE_BW,
        autoImport: false,
        agents: {},
        profile: { oidcSub: 'owner-sub', oidcEmail: 'owner@example.com', totpEnabled: false },
        oidc: {},
      },
    },
  )
  try {
    await broker.ready
    const port = broker.port
    const redirectUri = `http://127.0.0.1:${port}/oidc/callback`
    async function begin(bind, cookie) {
      const response = await fetch(`${broker.base}/oidc/login${bind ? '?bind=1' : ''}`, {
        headers: cookie ? { cookie } : {},
        redirect: 'manual',
      })
      return { status: response.status, location: response.headers.get('location') ?? '', cookie: cookieHeader(response), text: await response.text() }
    }
    const unbound = await begin(true)
    assert.equal(unbound.location.includes('/authorize'), false)
    assert.equal((unbound.cookie ?? '').includes('broker_oidc_bind=1'), false)

    const start = await begin(false)
    assert.equal(start.status, 302)
    const nonce = new URL(start.location).searchParams.get('nonce')
    const state = new URL(start.location).searchParams.get('state')
    const jar = start.cookie
    codes.set(
      'attacker',
      sign({
        iss: idp.base,
        aud: 'broker',
        sub: 'attacker-sub',
        nonce,
        exp: Math.floor(Date.now() / 1000) + 300,
      }),
    )
    const attack = await fetch(`${broker.base}/oidc/callback?code=attacker&state=${state}`, {
      headers: { cookie: jar },
      redirect: 'manual',
    })
    const attackCookie = cookieHeader(attack)
    assert.equal(attack.status === 302 && attackCookie.includes('broker_admin='), false)
    const attackBody = await attack.text()
    assert.match(attackBody, /OIDC|bound|owner|登录失败/i)

    const ownerStart = await begin(false)
    assert.equal(ownerStart.status, 302)
    const ownerNonce = new URL(ownerStart.location).searchParams.get('nonce')
    const ownerState = new URL(ownerStart.location).searchParams.get('state')
    codes.set(
      'owner',
      sign({
        iss: idp.base,
        aud: 'broker',
        sub: 'owner-sub',
        nonce: ownerNonce,
        exp: Math.floor(Date.now() / 1000) + 300,
      }),
    )
    const owner = await fetch(`${broker.base}/oidc/callback?code=owner&state=${ownerState}`, {
      headers: { cookie: ownerStart.cookie },
      redirect: 'manual',
    })
    assert.equal(owner.status, 302)
    const ownerCookie = cookieHeader(owner)
    assert.match(ownerCookie, /broker_admin=/)
    const status = await fetch(`${broker.base}/api/status`, { headers: { cookie: ownerCookie } })
    assert.equal(status.status, 200)

    const password = await login(broker.base)
    const bindStart = await begin(true, password.cookie)
    assert.equal(bindStart.status, 302)
    const bindNonce = new URL(bindStart.location).searchParams.get('nonce')
    const bindState = new URL(bindStart.location).searchParams.get('state')
    codes.set(
      'rebind',
      sign({
        iss: idp.base,
        aud: 'broker',
        sub: 'new-owner-sub',
        nonce: bindNonce,
        exp: Math.floor(Date.now() / 1000) + 300,
      }),
    )
    const rebound = await fetch(`${broker.base}/oidc/callback?code=rebind&state=${bindState}`, {
      headers: { cookie: `${password.cookie}; ${bindStart.cookie}` },
      redirect: 'manual',
    })
    assert.equal(rebound.status, 302)
    const saved = JSON.parse(await readFile(path.join(broker.home, 'config.json'), 'utf8'))
    assert.equal(saved.profile.oidcSub, 'new-owner-sub')
    assert.equal(redirectUri.endsWith('/oidc/callback'), true)
  } finally {
    await broker.stop()
    await idp.close()
  }
})

test('exec_with_secrets and wh.mjs mask output and drop the agent token', async () => {
  const broker = await startBroker()
  try {
    const agent = await provisionAgent(broker, {
      allow: 'gatewayapi',
      grant: { item: 'gatewayapi', ttlHours: 1, maxReads: 5 },
    })
    const script = `const fs=require('fs'); const v=process.env.X||''; const parent=fs.readFileSync('/proc/'+process.ppid+'/environ').toString('utf8'); const keys=parent.split('\\0').map(p=>p.split('=')[0]); process.stdout.write('VAL='+v+'\\n'); process.stdout.write('B64='+Buffer.from(v).toString('base64')+'\\n'); process.stdout.write('URL='+encodeURIComponent(v)+'\\n'); process.stdout.write('HEX='+Buffer.from(v).toString('hex')+'\\n'); process.stdout.write('TOK='+(process.env.BROKER_AGENT_TOKEN||'')+'\\n'); process.stdout.write('STOK='+(process.env.SECRETS_BROKER_TOKEN||'')+'\\n'); process.stdout.write('PPID_KEYS='+['BROKER_AGENT_TOKEN','SECRETS_BROKER_TOKEN','CF_ACCESS_CLIENT_SECRET','SECRETS_BROKER_ADMIN_PASSWORD'].filter(k=>keys.includes(k)).join(',')+'\\n');`
    const mcp = spawn(process.execPath, [path.join(ROOT, 'mcp-server.mjs')], {
      env: {
        ...process.env,
        BROKER_URL: broker.base,
        BROKER_AGENT_TOKEN: agent.token,
        SECRETS_BROKER_TOKEN: 'should-not-leak',
        MCP_ALLOW_READ: '0',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let stdout = ''
    mcp.stdout.on('data', (chunk) => {
      stdout += chunk
    })
    const call = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'exec_with_secrets', arguments: { command: process.execPath, args: ['-e', script], vars: { X: 'gatewayapi' } } },
    }
    mcp.stdin.write(`${JSON.stringify(call)}\n`)
    const line = await waitForLine(mcp, () => stdout.split('\n').find((entry) => entry.includes('"id":1') || entry.includes('"id": 1')))
    mcp.kill()
    const message = JSON.parse(line)
    const text = message.result?.content?.[0]?.text ?? message.error?.message ?? ''
    assert.equal(text.includes('GW-SECRET-1234'), false, text)
    assert.equal(text.includes(Buffer.from('GW-SECRET-1234').toString('base64')), false, text)
    assert.equal(text.includes(encodeURIComponent('GW-SECRET-1234')), false, text)
    assert.equal(text.includes(Buffer.from('GW-SECRET-1234').toString('hex')), false, text)
    assert.match(text, /PPID_KEYS=\s/)
    assert.equal(text.includes(agent.token), false, text)
    assert.equal(text.includes('should-not-leak'), false, text)
    assert.match(text, /\[redacted\]/)

    const helper = spawn(process.execPath, [path.join(ROOT, 'wh.mjs'), 'run', '--var', 'X=gatewayapi', '--', process.execPath, '-e', script], {
      env: {
        ...process.env,
        SECRETS_BROKER_URL: broker.base,
        SECRETS_BROKER_TOKEN: agent.token,
        BROKER_AGENT_TOKEN: 'parent-token',
      },
    })
    let helperOut = ''
    helper.stdout.on('data', (chunk) => {
      helperOut += chunk
    })
    const helperCode = await new Promise((resolve) => helper.once('exit', resolve))
    assert.equal(helperCode, 0, helperOut)
    assert.equal(helperOut.includes('GW-SECRET-1234'), false, helperOut)
    assert.equal(helperOut.includes(Buffer.from('GW-SECRET-1234').toString('base64')), false, helperOut)
    assert.equal(helperOut.includes(Buffer.from('GW-SECRET-1234').toString('hex')), false, helperOut)
    assert.match(helperOut, /PPID_KEYS=\s/)
    assert.equal(helperOut.includes(agent.token), false, helperOut)
    assert.equal(helperOut.includes('parent-token'), false, helperOut)

    const splitScript = `const v=process.env.X||''; process.stdout.write(v.slice(0,4)); setTimeout(()=>process.stdout.write(v.slice(4)), 300)`
    const splitter = spawn(process.execPath, [path.join(ROOT, 'wh.mjs'), 'run', '--var', 'X=gatewayapi', '--', process.execPath, '-e', splitScript], {
      env: {
        ...process.env,
        SECRETS_BROKER_URL: broker.base,
        SECRETS_BROKER_TOKEN: agent.token,
        BROKER_AGENT_TOKEN: 'parent-token',
      },
    })
    let splitOut = ''
    splitter.stdout.on('data', (chunk) => {
      splitOut += chunk
    })
    const splitCode = await new Promise((resolve) => splitter.once('exit', resolve))
    assert.equal(splitCode, 0, splitOut)
    assert.equal(splitOut.includes('GW-SECRET-1234'), false, splitOut)
    assert.equal(splitOut.includes('GW-SE'), false, splitOut)
    assert.equal(splitOut.includes('CRET-1234'), false, splitOut)
  } finally {
    await broker.stop()
  }
})

test('stdio clients send Cloudflare Access service-token headers', async () => {
  const seen = []
  const fake = await listen((req, res) => {
    seen.push(req.headers)
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ value: 'GW-SECRET-1234', items: [] }))
  })
  const env = {
    ...process.env,
    BROKER_URL: fake.base,
    SECRETS_BROKER_URL: fake.base,
    BROKER_AGENT_TOKEN: 'agent-token',
    SECRETS_BROKER_TOKEN: 'agent-token',
    CF_ACCESS_CLIENT_ID: 'cf-id.access',
    CF_ACCESS_CLIENT_SECRET: 'cf-secret-value',
  }
  try {
    const mcp = spawn(process.execPath, [path.join(ROOT, 'mcp-server.mjs')], { env, stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    mcp.stdout.on('data', (chunk) => {
      stdout += chunk
    })
    mcp.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'list_secrets', arguments: {} } })}\n`)
    await waitForLine(mcp, () => stdout.split('\n').find((entry) => entry.includes('"id":7') || entry.includes('"id": 7')))
    mcp.kill()
    const helper = spawn(process.execPath, [path.join(ROOT, 'wh.mjs'), 'get', 'gatewayapi'], { env })
    await new Promise((resolve) => helper.once('exit', resolve))
    assert.equal(seen.length >= 2, true)
    for (const headers of seen) {
      assert.equal(headers['cf-access-client-id'], 'cf-id.access')
      assert.equal(headers['cf-access-client-secret'], 'cf-secret-value')
    }
  } finally {
    await fake.close()
  }
})

test('restore does not turn an expired grant into a permanent one', async () => {
  const broker = await startBroker()
  try {
    const agent = await provisionAgent(broker, { allow: 'gatewayapi', grant: { item: 'gatewayapi', ttlHours: 1, maxReads: 1 } })
    await adminPost(broker.base, agent.cookie, '/api/grants/set-expiry', {
      agent: 'bot',
      name: 'gatewayapi',
      expiresAt: new Date(Date.now() - 5000).toISOString(),
    })
    await adminPost(broker.base, agent.cookie, '/api/grants/restore', { agent: 'bot', name: 'gatewayapi' })
    const listed = await fetch(`${broker.base}/api/grants-list`, { headers: { cookie: agent.cookie } })
    const body = await listed.json()
    const grant = body.grants.find((entry) => entry.agent === 'bot' && entry.name === 'gatewayapi')
    assert.ok(grant)
    assert.notEqual(grant.expiresAt, null)
    assert.equal(grant.active, false)
  } finally {
    await broker.stop()
  }
})

test('the literal bearer token oauth does not authenticate an oauth agent', async () => {
  const placeholderHash = `sha256:${crypto.createHash('sha256').update('oauth').digest('hex')}`
  const broker = await startBroker(
    {},
    {
      config: {
        port: 8788,
        serverUrl: 'https://vault.example.com',
        bwJs: FAKE_BW,
        autoImport: false,
        agents: {
          'oauth:plain': 'oauth',
          'oauth:hashed': placeholderHash,
          keeper: 'keeper-token-value',
        },
        agentAccess: {
          'oauth:plain': ['gatewayapi'],
          'oauth:hashed': ['gatewayapi'],
          keeper: ['gatewayapi'],
        },
        oauthClients: {
          plain: { clientId: 'plain', redirectUris: ['https://app.example/cb'], revoked: false },
          hashed: { clientId: 'hashed', redirectUris: ['https://app.example/cb'], revoked: false },
        },
      },
    },
  )
  const children = [broker.child]
  try {
    await broker.ready
    const saved = JSON.parse(await readFile(path.join(broker.home, 'config.json'), 'utf8'))
    assert.equal(saved.agents['oauth:plain'], null)
    assert.equal(saved.agents['oauth:hashed'], null)
    assert.equal(JSON.stringify(saved.agents).includes(placeholderHash), false)
    let keeper
    for (let attempt = 0; attempt < 40; attempt += 1) {
      keeper = await fetch(`${broker.base}/secret?name=gatewayapi`, {
        headers: { authorization: 'Bearer keeper-token-value' },
      })
      if (keeper.status !== 503) break
      await sleep(50)
    }
    assert.equal(keeper.status, 202)
    const stolen = await fetch(`${broker.base}/agent/items`, { headers: { authorization: 'Bearer oauth' } })
    assert.equal(stolen.status, 401)
    const stolenSecret = await fetch(`${broker.base}/secret?name=gatewayapi`, { headers: { authorization: 'Bearer oauth' } })
    assert.equal(stolenSecret.status, 401)

    broker.child.kill('SIGTERM')
    await new Promise((resolve) => broker.child.once('exit', resolve))
    const port = await freePort()
    const relaunched = spawn(process.execPath, [SERVER], {
      cwd: ROOT,
      env: { ...broker.env, SECRETS_BROKER_PORT: String(port), BROKER_PUBLIC_URL: `http://127.0.0.1:${port}`, SECRETS_BROKER_OAUTH: '0' },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    children.push(relaunched)
    let logs = ''
    relaunched.stdout.on('data', (chunk) => {
      logs += chunk
    })
    relaunched.stderr.on('data', (chunk) => {
      logs += chunk
    })
    const deadline = Date.now() + 8000
    while (Date.now() < deadline && !logs.includes('listening')) {
      if (relaunched.exitCode !== null) throw new Error(logs)
      await sleep(30)
    }
    const again = await fetch(`http://127.0.0.1:${port}/agent/items`, { headers: { authorization: 'Bearer oauth' } })
    assert.equal(again.status, 401)
    let keeperAgain
    for (let attempt = 0; attempt < 40; attempt += 1) {
      keeperAgain = await fetch(`http://127.0.0.1:${port}/secret?name=gatewayapi`, {
        headers: { authorization: 'Bearer keeper-token-value' },
      })
      if (keeperAgain.status !== 503) break
      await sleep(50)
    }
    assert.equal(keeperAgain.status, 202)
    relaunched.kill('SIGTERM')
  } finally {
    for (const child of children) {
      if (child.exitCode === null) child.kill('SIGKILL')
    }
    await broker.stop()
  }
})

test('login lockout does not block oauth approval', async () => {
  const broker = await startBroker({ SECRETS_BROKER_OAUTH: '1' })
  try {
    await broker.ready
    for (let attempt = 0; attempt < 6; attempt += 1) {
      const response = await fetch(`${broker.base}/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ password: 'wrong-password' }),
        redirect: 'manual',
      })
      if (attempt < 5) assert.notEqual(response.status, 429)
      else assert.equal(response.status, 429)
    }
    const approve = await fetch(`${broker.base}/oauth/approve`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: 'missing',
        redirect_uri: 'https://app.example/cb',
        password: 'wrong-password',
        decision: 'allow',
      }),
    })
    assert.notEqual(approve.status, 429)
    const text = await approve.text()
    assert.equal(text.includes('code='), false)
  } finally {
    await broker.stop()
  }
})

test('a bot cannot keep more than five pending requests', async () => {
  const broker = await startBroker()
  try {
    const agent = await provisionAgent(broker, { allow: '*' })
    const statuses = []
    for (let index = 1; index <= 6; index += 1) {
      const response = await fetch(`${broker.base}/secret?name=flood-${index}`, {
        headers: { authorization: `Bearer ${agent.token}` },
      })
      statuses.push(response.status)
    }
    assert.deepEqual(statuses, [202, 202, 202, 202, 202, 429])
    const again = await fetch(`${broker.base}/secret?name=flood-1`, {
      headers: { authorization: `Bearer ${agent.token}` },
    })
    assert.equal(again.status, 202)
    const pending = await fetch(`${broker.base}/api/pending`, { headers: { cookie: agent.cookie } })
    const rows = (await pending.json()).requests.filter((entry) => entry.agent === 'bot')
    assert.equal(rows.length, 5)
  } finally {
    await broker.stop()
  }
})

test('expired one-time approval tokens are dropped', async () => {
  const ntfy = await listen((req, res) => {
    let body = ''
    req.on('data', (chunk) => {
      body += chunk
    })
    req.on('end', () => {
      ntfy.requests.push({ headers: req.headers, body })
      res.writeHead(200)
      res.end('ok')
    })
  })
  ntfy.requests = []
  const broker = await startBroker({
    NTFY_URL: `${ntfy.base}/secrets`,
    NTFY_TOKEN: 'ntfy-private-token',
    SECRETS_BROKER_APPROVAL_TOKEN_TTL_MS: '1500',
  })
  try {
    const agent = await provisionAgent(broker, { allow: 'gatewayapi' })
    const pending = await fetch(`${broker.base}/secret?name=gatewayapi`, {
      headers: { authorization: `Bearer ${agent.token}` },
    })
    assert.equal(pending.status, 202)
    await waitFor(() => ntfy.requests.length > 0)
    const actions = JSON.parse(ntfy.requests[0].headers.actions ?? '[]')
    const once = actions.find((action) => /once/i.test(action.label))
    const token = String(once.headers?.Authorization ?? once.headers?.authorization ?? '').replace(/^Bearer /, '')
    const before = await fetch(`${broker.base}/api/status`, { headers: { cookie: agent.cookie } })
    assert.equal((await before.json()).approvalTokens, 4)
    await sleep(1700)
    const after = await fetch(`${broker.base}/api/status`, { headers: { cookie: agent.cookie } })
    assert.equal((await after.json()).approvalTokens, 0)
    const late = await fetch(once.url, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: 'decision=once',
    })
    const lateText = await late.text()
    assert.equal(lateText.includes('已选择'), false)
  } finally {
    await broker.stop()
    await ntfy.close()
  }
})

test('redactor holds a secret split across chunks and masks hex', () => {
  const secret = 'GW-SECRET-1234'
  const redactor = createRedactor([secret])
  let out = ''
  for (const char of secret) out += redactor.push(char)
  out += redactor.flush()
  assert.equal(out.includes(secret), false, out)
  assert.match(out, /\[redacted\]/)
  const hex = Buffer.from(secret).toString('hex')
  const hexRedactor = createRedactor([secret])
  let hexOut = hexRedactor.push(hex.slice(0, 10))
  hexOut += hexRedactor.push(hex.slice(10))
  hexOut += hexRedactor.flush()
  assert.equal(hexOut.toLowerCase().includes(hex), false, hexOut)
})

test('dockerfile runs as non-root and compose publishes loopback only', async () => {
  const dockerfile = await readFile(path.join(ROOT, 'deploy', 'Dockerfile'), 'utf8')
  const compose = await readFile(path.join(ROOT, 'docker-compose.yml'), 'utf8')
  const deployCompose = await readFile(path.join(ROOT, 'deploy', 'docker-compose.yml'), 'utf8')
  assert.match(dockerfile, /^USER [a-z0-9_-]+/m)
  assert.doesNotMatch(dockerfile, /^USER root/m)
  assert.match(dockerfile, /sha256:[a-f0-9]{64}/)
  assert.match(compose, /127\.0\.0\.1:8788:8788/)
  assert.match(deployCompose, /127\.0\.0\.1:8788:8788/)
  assert.equal(redactSecrets('GW-SECRET-1234', ['GW-SECRET-1234']).includes('GW-SECRET-1234'), false)
})

function listen(handler) {
  const server = http.createServer(handler)
  const closed = new Promise((resolve) => {
    server.on('close', resolve)
  })
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      resolve({
        base: `http://127.0.0.1:${port}`,
        close: () =>
          new Promise((done) => {
            server.close(() => done())
            return closed
          }),
      })
    })
  })
}

async function waitFor(predicate, timeoutMs = 4000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) return
    await sleep(30)
  }
  throw new Error('timed out waiting for condition')
}

function waitForLine(child, pick) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out waiting for mcp output')), 8000)
    const check = () => {
      try {
        const line = pick()
        if (line) {
          clearTimeout(timer)
          resolve(line)
        }
      } catch (error) {
        clearTimeout(timer)
        reject(error)
      }
    }
    child.stdout.on('data', check)
    child.on('exit', check)
  })
}
