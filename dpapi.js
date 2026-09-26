/**
 * Seal and unseal a byte payload with the Windows Data Protection API (DPAPI)
 * under the current OS user.
 *
 * DPAPI derives its master key from the signed-in user's credential and keeps
 * it in that user's profile, bound to both the user and the machine; where the
 * hardware carries a TPM, Windows protects that master key with it. Node ships
 * no DPAPI binding, so the call goes through the OS PowerShell host, which
 * exists on every supported Windows version. The payload travels on stdin as
 * base64 and returns on stdout as base64, so neither the plaintext nor the
 * sealed bytes ever reach a command line — and therefore never the process
 * table or a shell history.
 *
 * One DPAPI call costs a process spawn, so this module is used once per store
 * lifetime to seal a randomly generated AES key; the payloads themselves are
 * sealed in-process by `envelope.js`.
 *
 * A failure is surfaced, never swallowed: a provider that cannot seal must
 * refuse to store rather than quietly fall back to plaintext.
 * @module dsh-destinywind-tpm/dpapi
 */

import { spawn } from 'node:child_process'

/** PowerShell hosts probed in order; the first that answers is reused. */
const SHELL_CANDIDATES = Object.freeze(['powershell.exe', 'pwsh.exe', 'powershell', 'pwsh'])

/** Wall-clock budget for one DPAPI round trip; a cold host pays startup. */
const CALL_TIMEOUT_MS = 30_000

/** Common preamble: strict errors plus the assembly that carries ProtectedData. */
const PREAMBLE = [
  "$ErrorActionPreference = 'Stop'",
  'Add-Type -AssemblyName System.Security',
  '$raw = [Console]::In.ReadToEnd().Trim()',
  '$bytes = [Convert]::FromBase64String($raw)',
  '$scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser',
].join('\n')

/** Seal the payload, returning the DPAPI blob as base64. */
const PROTECT_SCRIPT = `${PREAMBLE}\n$out = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, $scope)\n[Console]::Out.Write([Convert]::ToBase64String($out))`

/** Unseal the payload, returning the original bytes as base64. */
const UNPROTECT_SCRIPT = `${PREAMBLE}\n$out = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, $scope)\n[Console]::Out.Write([Convert]::ToBase64String($out))`

/** The host that answered last, so the probe cost is paid once. */
let resolvedShell

/** Encode one script the way `-EncodedCommand` expects (UTF-16LE, base64). */
function encodeCommand(script) {
  return Buffer.from(script, 'utf16le').toString('base64')
}

/**
 * Run one script with `payload` on stdin and resolve with its stdout.
 * @param {string} shell - executable name or absolute path of the PowerShell host.
 * @param {string} script - the script source to run.
 * @param {string} payload - base64 text written to stdin.
 * @returns {Promise<string>} the trimmed stdout.
 */
function runScript(shell, script, payload) {
  return new Promise((resolve, reject) => {
    const child = spawn(shell, ['-NoProfile', '-NonInteractive', '-EncodedCommand', encodeCommand(script)], {
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    const out = []
    const err = []
    let settled = false
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      child.kill()
      reject(new Error(`dpapi: ${shell} did not answer within ${String(CALL_TIMEOUT_MS)} ms`))
    }, CALL_TIMEOUT_MS)
    /** Settle once; later events from the same child are ignored. */
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error === undefined) resolve(value)
      else reject(error)
    }
    child.stdout.on('data', chunk => out.push(chunk))
    child.stderr.on('data', chunk => err.push(chunk))
    child.on('error', error => { finish(error) })
    child.on('close', (code) => {
      if (code !== 0) {
        const detail = Buffer.concat(err).toString('utf8').trim()
        finish(new Error(`dpapi: ${shell} exited with code ${String(code)}${detail.length > 0 ? `: ${detail}` : ''}`))
        return
      }
      finish(undefined, Buffer.concat(out).toString('utf8').trim())
    })
    // An early exit closes the pipe; the close handler owns the real report.
    child.stdin.on('error', () => {})
    child.stdin.end(payload)
  })
}

/**
 * Run one script, probing the candidate hosts on first use.
 * @param {string} script - the script source to run.
 * @param {string} payload - base64 text written to stdin.
 * @returns {Promise<string>} the trimmed stdout.
 */
async function run(script, payload) {
  if (resolvedShell !== undefined) return await runScript(resolvedShell, script, payload)
  const failures = []
  for (const shell of SHELL_CANDIDATES) {
    try {
      const result = await runScript(shell, script, payload)
      resolvedShell = shell
      return result
    } catch (error) {
      failures.push(`${shell}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  throw new Error(`dpapi: no usable PowerShell host (${failures.join('; ')})`)
}

/**
 * Seal one payload under the current OS user.
 * @param {Buffer} bytes - plaintext bytes to seal.
 * @returns {Promise<Buffer>} the DPAPI blob.
 */
export async function sealBytes(bytes) {
  return Buffer.from(await run(PROTECT_SCRIPT, bytes.toString('base64')), 'base64')
}

/**
 * Unseal one DPAPI blob produced by {@link sealBytes} for this user.
 * @param {Buffer} blob - the sealed bytes.
 * @returns {Promise<Buffer>} the original plaintext bytes.
 */
export async function unsealBytes(blob) {
  return Buffer.from(await run(UNPROTECT_SCRIPT, blob.toString('base64')), 'base64')
}

/**
 * Whether a full DPAPI round trip succeeds on this machine.
 * @returns {Promise<boolean>} true when sealing and unsealing both work.
 */
export async function dpapiAvailable() {
  const probe = 'dsh-dpapi-probe'
  try {
    const opened = await unsealBytes(await sealBytes(Buffer.from(probe, 'utf8')))
    return opened.toString('utf8') === probe
  } catch {
    return false
  }
}
