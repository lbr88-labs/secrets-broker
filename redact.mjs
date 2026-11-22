/**
 * Redact secret values (and common encodings) from process output, and build a
 * child environment that does not inherit the broker or Cloudflare Access tokens.
 */

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
