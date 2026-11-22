#!/usr/bin/env node
/**
 * Stand-in for the Bitwarden CLI. Prints two dummy items and never contacts a vault.
 * FAKE_BW_DELAY_MS delays `list` so tests can race the broker's read path.
 */
const delayMs = Number(process.env.FAKE_BW_DELAY_MS ?? 0)
const items = [
  {
    id: '1',
    name: 'gatewayapi',
    type: 1,
    login: { username: '', password: 'GW-SECRET-1234', uris: [{ uri: 'https://aws.amazon.com' }] },
    notes: null,
    fields: [],
  },
  {
    id: '2',
    name: 'other-key',
    type: 1,
    login: { username: '', password: 'OTHER-SECRET-9999', uris: [{ uri: 'https://example.com' }] },
    notes: null,
    fields: [],
  },
]

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

let stdin = ''
process.stdin.on('data', (chunk) => {
  stdin += chunk
})
process.stdin.on('end', async () => {
  const args = process.argv.slice(2)
  if (delayMs > 0 && args[0] === 'list') await sleep(delayMs)
  const cmd = args[0]
  if (cmd === 'unlock') {
    process.stdout.write('fake-session\n')
    process.exit(0)
  }
  if (cmd === 'sync' || cmd === 'login' || cmd === 'config' || cmd === 'status') process.exit(0)
  if (cmd === 'list') {
    process.stdout.write(JSON.stringify(items))
    process.exit(0)
  }
  if (cmd === 'get' && args[1] === 'template') {
    process.stdout.write(JSON.stringify({ type: 1, name: '', notes: null, login: { username: '', password: '', uris: [] } }))
    process.exit(0)
  }
  if (cmd === 'get' && args[1] === 'item') {
    const item = items.find((candidate) => candidate.id === args[2]) ?? {}
    process.stdout.write(JSON.stringify(item))
    process.exit(0)
  }
  if (cmd === 'encode') {
    process.stdout.write(`${stdin.trim()}\n`)
    process.exit(0)
  }
  if (cmd === 'edit' || cmd === 'create' || cmd === 'delete') process.exit(0)
  process.stderr.write(`fake-bw: unknown command ${args.join(' ')}\n`)
  process.exit(1)
})
