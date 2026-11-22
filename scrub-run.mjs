#!/usr/bin/env node
/**
 * Parent of a user command. Started with a scrubbed environment so
 * /proc/$PPID/environ does not contain broker tokens. The command line and
 * the environment to run are read from fd 3 and that fd is closed before the
 * command starts.
 */
import fs from 'node:fs'
import { spawn } from 'node:child_process'

const raw = fs.readFileSync(3, 'utf8')
fs.closeSync(3)
const { command, args, env } = JSON.parse(raw)
const child = spawn(command, args ?? [], {
  env,
  stdio: ['inherit', 'inherit', 'inherit'],
})
child.on('error', () => process.exit(127))
child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal)
    return
  }
  process.exit(code ?? 1)
})
