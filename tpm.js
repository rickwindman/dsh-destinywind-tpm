/**
 * Seal and unseal a byte payload with a machine-resident TPM-backed key.
 *
 * The data key that protects every credential is wrapped by an RSA key that
 * lives inside the platform's trusted module, so unwrapping it requires that
 * exact machine. Node ships no CNG binding, so the call goes through the OS
 * PowerShell host; the payload travels on stdin as base64 and returns on stdout
 * as base64, so neither the plaintext nor the wrapped bytes ever reach a
 * command line — and therefore never the process table or a shell history.
 *
 * The provider is named by a literal string rather than by the
 * `CngProvider.MicrosoftPlatformCryptoProvider` static property: Windows
 * PowerShell 5.1 resolves that property to the empty string, and opening a
 * provider by an empty name fails with NTE_PROVIDER_NOT_FOUND (0x80090017).
 * The literal resolves to the same provider on every supported version.
 *
 * A failure is surfaced, never swallowed: a protector that cannot seal must
 * refuse to store rather than quietly fall back to a weaker layer.
 * @module dsh-destinywind-tpm/tpm
 */

import { spawn } from 'node:child_process'

/** PowerShell hosts probed in order; the first that answers is reused. */
const SHELL_CANDIDATES = Object.freeze(['powershell.exe', 'pwsh.exe', 'powershell', 'pwsh'])

/** Wall-clock budget for one round trip; a cold host pays startup. */
const CALL_TIMEOUT_MS = 30_000

/**
 * Most TPMs accept only a few keys, and a key that outlives the store must be
 * findable again on the next boot, so one stable name is used per store.
 */
const KEY_NAME = 'dsh-credentials-tpm-v1'

/**
 * The provider name is spelled out rather than read from the `CngProvider`
 * static property, which is empty on Windows PowerShell 5.1.
 */
const PROVIDER_NAME = 'Microsoft Platform Crypto Provider'

/** Build the script that wraps or unwraps the payload. */
function buildScript(mode) {
  const verb = mode === 'seal' ? 'Encrypt' : 'Decrypt'
  return [
    "$ErrorActionPreference = 'Stop'",
    `$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER_NAME}')`,
    `$key = [System.Security.Cryptography.CngKey]::Open('${KEY_NAME}', $provider)`,
    '$rsa = [System.Security.Cryptography.RSACng]::new($key)',
    '$raw = [Console]::In.ReadToEnd().Trim()',
    '$bytes = [Convert]::FromBase64String($raw)',
    '$padding = [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1',
    `$out = $rsa.${verb}($bytes, $padding)`,
    '$rsa.Dispose()',
    '$key.Dispose()',
    '[Console]::Out.Write([Convert]::ToBase64String($out))',
  ].join('\n')
}

/** Create the wrapping key, or replace it when one is already present. */
const CREATE_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  `$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER_NAME}')`,
  '$parameters = [System.Security.Cryptography.CngKeyCreationParameters]::new()',
  '$parameters.Provider = $provider',
  '$parameters.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None',
  '$parameters.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::AllUsages',
  '$parameters.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::OverwriteExistingKey',
  `$key = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, '${KEY_NAME}', $parameters)`,
  '$key.Dispose()',
  '[Console]::Out.Write("ok")',
].join('\n')

const SEAL_SCRIPT = buildScript('seal')
const UNSEAL_SCRIPT = buildScript('unseal')

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
      reject(new Error(`tpm: ${shell} did not answer within ${String(CALL_TIMEOUT_MS)} ms`))
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
        finish(new Error(`tpm: ${shell} exited with code ${String(code)}${detail.length > 0 ? `: ${detail}` : ''}`))
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
  throw new Error(`tpm: no usable PowerShell host (${failures.join('; ')})`)
}

/** The host probe: a script with no payload that only needs the provider. */
async function runNoPayload(script) {
  return await run(script, '')
}

/** Create the TPM-resident wrapping key. */
export async function createKey() {
  await runNoPayload(CREATE_SCRIPT)
}

/**
 * Wrap one payload with the TPM-resident key.
 * @param {Buffer} bytes - plaintext bytes to wrap.
 * @returns {Promise<Buffer>} the wrapped bytes.
 */
export async function sealBytes(bytes) {
  return Buffer.from(await run(SEAL_SCRIPT, bytes.toString('base64')), 'base64')
}

/**
 * Unwrap one payload produced by {@link sealBytes} on this machine.
 * @param {Buffer} blob - the wrapped bytes.
 * @returns {Promise<Buffer>} the original plaintext bytes.
 */
export async function unsealBytes(blob) {
  return Buffer.from(await run(UNSEAL_SCRIPT, blob.toString('base64')), 'base64')
}

/**
 * Whether a TPM-backed wrapping key can be created and used on this machine.
 *
 * The probe creates the key, wraps and unwraps a sample, and reports success
 * only when the bytes come back identical — a TPM that answers but returns
 * something else is worse than one that refuses, because the store would look
 * healthy while holding data it can no longer read.
 * @returns {Promise<boolean>} true when a full round trip succeeds.
 */
export async function tpmAvailable() {
  const probe = 'dsh-tpm-availability-probe'
  try {
    await createKey()
    const opened = await unsealBytes(await sealBytes(Buffer.from(probe, 'utf8')))
    return opened.toString('utf8') === probe
  } catch {
    return false
  }
}
