/**
 * Redact secret values (and common encodings) from process output, and build a
 * child environment that does not inherit the broker or Cloudflare Access tokens.
 *
 * This is a guard against accidental disclosure. It does not stop a command that
 * wants the value: a prefix, a reversed or spaced string, or an encoding of the
 * value with extra text still comes through. The user command's parent is a
 * short-lived runner started without these secrets, so /proc/$PPID/environ does
 * not contain them. The helper process that spawned that runner still has the
 * original environment, and so does the harness MCP config.
 */
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const TOKEN_ENV_KEYS = [
  'BROKER_AGENT_TOKEN',
  'SECRETS_BROKER_TOKEN',
  'CF_ACCESS_CLIENT_ID',
  'CF_ACCESS_CLIENT_SECRET',
  'SECRETS_BROKER_ADMIN_PASSWORD',
  'SECRETS_BROKER_MASTER_PASSWORD',
  'SECRETS_BROKER_ENCRYPTION_KEY',
]

export function secretVariants(secret) {
  const value = String(secret ?? '')
  if (value.length === 0) return []
  const variants = new Set([value])
  const base64 = Buffer.from(value, 'utf8').toString('base64')
  variants.add(base64)
  variants.add(base64.replace(/=+$/, ''))
  variants.add(Buffer.from(value, 'utf8').toString('base64url'))
  variants.add(encodeURIComponent(value))
  const hex = Buffer.from(value, 'utf8').toString('hex')
  variants.add(hex)
  variants.add(hex.toUpperCase())
  return [...variants].filter((variant) => variant.length > 0)
}

export function redactSecrets(text, secrets) {
  let out = String(text ?? '')
  const variants = []
  for (const secret of secrets ?? []) variants.push(...secretVariants(secret))
  variants.sort((a, b) => b.length - a.length)
  for (const variant of variants) {
    if (!variant) continue
    out = out.split(variant).join('[redacted]')
  }
  return out
}

export function createRedactor(secrets) {
  const variants = []
  for (const secret of secrets ?? []) variants.push(...secretVariants(secret))
  const unique = [...new Set(variants)].filter(Boolean).sort((a, b) => b.length - a.length)
  const max = unique.reduce((length, variant) => Math.max(length, variant.length), 0)
  let pending = ''
  if (max === 0) {
    return {
      push(chunk) {
        return String(chunk ?? '')
      },
      flush() {
        return ''
      },
    }
  }
  const hold = max - 1
  return {
    push(chunk) {
      pending += String(chunk ?? '')
      if (pending.length <= hold) return ''
      let end = pending.length - hold
      for (let guard = 0; guard < unique.length + 2; guard += 1) {
        let extended = end
        for (const variant of unique) {
          const from = Math.max(0, end - variant.length + 1)
          let index = pending.indexOf(variant, from)
          while (index !== -1 && index < end) {
            const variantEnd = index + variant.length
            if (variantEnd > extended) extended = variantEnd
            index = pending.indexOf(variant, index + 1)
          }
        }
        if (extended === end) break
        end = Math.min(extended, pending.length)
      }
      const piece = pending.slice(0, end)
      pending = pending.slice(end)
      return redactSecrets(piece, secrets)
    },
    flush() {
      const out = redactSecrets(pending, secrets)
      pending = ''
      return out
    },
  }
}

const runnerPath = fileURLToPath(new URL('./scrub-run.mjs', import.meta.url))

export function scrubbedProcessEnv(base = process.env) {
  const env = { ...base }
  for (const key of TOKEN_ENV_KEYS) delete env[key]
  return env
}

/** Run a command whose parent process was started without broker secrets in its environment. */
export function spawnUserCommand(command, args, env, { stdin = 'inherit' } = {}) {
  const child = spawn(process.execPath, [runnerPath], {
    env: scrubbedProcessEnv(),
    stdio: [stdin, 'pipe', 'pipe', 'pipe'],
  })
  child.stdio[3].end(JSON.stringify({ command, args, env }))
  return child
}

export function childEnv(base, injected) {
  const env = { ...base, ...injected }
  for (const key of TOKEN_ENV_KEYS) delete env[key]
  return env
}

export function accessHeaders(headers = {}) {
  const id = process.env.CF_ACCESS_CLIENT_ID ?? ''
  const secret = process.env.CF_ACCESS_CLIENT_SECRET ?? ''
  if (!id || !secret) return headers
  return {
    ...headers,
    'CF-Access-Client-Id': id,
    'CF-Access-Client-Secret': secret,
  }
}
