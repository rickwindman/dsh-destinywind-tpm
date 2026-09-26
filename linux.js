/**
 * Platform protectors for Linux, where neither DPAPI nor CNG exists.
 *
 * Two backends are tried in order of strength. A TPM 2.0 device gives the same
 * property the Windows path gives — the data key is wrapped by a key that never
 * leaves the module, so the store is unreadable on any other machine. Where no
 * usable TPM is present, the session keyring (libsecret) is used instead: it is
 * unlocked by the user's login and is still a secret store rather than a file,
 * but it does not bind the data to this machine.
 *
 * Both backends are optional and probe before use. If neither answers, the
 * provider refuses to mount rather than storing credentials in the clear: on
 * Linux a plain file under the home directory is exactly what this plugin
 * exists to stop doing.
 * @module dsh-destinywind-tpm/linux
 */

import { spawn } from 'node:child_process'
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

/** Wall-clock budget for one helper invocation. */
const CALL_TIMEOUT_MS = 30_000

/** Attributes that address this plugin's entry inside the session keyring. */
const KEYRING_ATTRIBUTES = ['service', 'dsh', 'application', 'dsh-credentials']

/**
 * Run one command and resolve with its stdout.
 * @param {string} command - the executable.
 * @param {string[]} args - arguments.
 * @param {Buffer | string | undefined} stdin - bytes written to stdin.
 * @returns {Promise<Buffer>} the raw stdout.
 */
function run(command, args, stdin) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] })
    const out = []
    const err = []
    let settled = false
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      child.kill()
      reject(new Error(`${command} did not answer within ${String(CALL_TIMEOUT_MS)} ms`))
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
        finish(new Error(`${command} exited with code ${String(code)}${detail.length > 0 ? `: ${detail}` : ''}`))
        return
      }
      finish(undefined, Buffer.concat(out))
    })
    child.stdin.on('error', () => {})
    child.stdin.end(stdin ?? '')
  })
}

/** Whether one executable can be launched at all. */
async function hasCommand(command, args) {
  try {
    await run(command, args)
    return true
  } catch {
    return false
  }
}

/**
 * Load (or create) the TPM-resident wrapping key and return its context path.
 *
 * The primary object is created in the owner hierarchy on first use and cached;
 * the child key's public and private blobs are stored beside it, so a later boot
 * reloads the same key instead of minting one that would orphan the store.
 * @param {string} dir - directory holding the TPM artefacts.
 * @returns {Promise<string>} path of the loaded key context.
 */
async function ensureTpmKey(dir) {
  await mkdir(dir, { recursive: true, mode: 0o700 })
  const primary = join(dir, 'tpm2-primary.ctx')
  const pub = join(dir, 'tpm2-key.pub')
  const priv = join(dir, 'tpm2-key.priv')
  const context = join(dir, 'tpm2-key.ctx')
  try {
    await readFile(primary)
  } catch {
    await run('tpm2_createprimary', ['-C', 'o', '-G', 'rsa', '-c', primary])
  }
  try {
    await readFile(pub)
    await readFile(priv)
  } catch {
    await run('tpm2_create', ['-C', primary, '-G', 'rsa', '-u', pub, '-r', priv])
  }
  await run('tpm2_load', ['-C', primary, '-u', pub, '-r', priv, '-c', context])
  return context
}

/**
 * Build the Linux protector set.
 * @param {{keyDir?: string}} [options] - where the TPM artefacts are kept.
 * @returns {{tpm2: object, secretService: object}} the two candidate protectors.
 */
export function linuxProtectors(options = {}) {
  const dir = options.keyDir ?? join(process.env.HOME ?? '/tmp', '.dsh', 'credentials-tpm')

  /** Round-trip one payload through the TPM, or through the keyring. */
  const tpm2 = {
    async available() {
      if (!await hasCommand('tpm2_getcap', ['properties-fixed'])) return false
      const probe = 'dsh-tpm-availability-probe'
      try {
        const context = await ensureTpmKey(dir)
        const input = join(dir, 'probe.in')
        const output = join(dir, 'probe.out')
        await writeFile(input, Buffer.from(probe, 'utf8'))
        await run('tpm2_encryptdecrypt', ['-c', context, '-i', input, '-o', output])
        await run('tpm2_encryptdecrypt', ['-d', '-c', context, '-i', output, '-o', input])
        const back = await readFile(input, 'utf8')
        await rm(input, { force: true })
        await rm(output, { force: true })
        return back === probe
      } catch {
        return false
      }
    },
    async sealBytes(bytes) {
      const context = await ensureTpmKey(dir)
      const input = join(dir, `in-${String(process.pid)}`)
      const output = join(dir, `out-${String(process.pid)}`)
      await writeFile(input, bytes)
      try {
        await run('tpm2_encryptdecrypt', ['-c', context, '-i', input, '-o', output])
        return await readFile(output)
      } finally {
        await rm(input, { force: true })
        await rm(output, { force: true })
      }
    },
    async unsealBytes(blob) {
      const context = await ensureTpmKey(dir)
      const input = join(dir, `in-${String(process.pid)}`)
      const output = join(dir, `out-${String(process.pid)}`)
      await writeFile(input, blob)
      try {
        await run('tpm2_encryptdecrypt', ['-d', '-c', context, '-i', input, '-o', output])
        return await readFile(output)
      } finally {
        await rm(input, { force: true })
        await rm(output, { force: true })
      }
    },
  }

  const secretService = {
    async available() {
      if (!await hasCommand('secret-tool', ['lookup', ...KEYRING_ATTRIBUTES])) {
        // `lookup` exits non-zero when the entry is absent, so only a missing
        // executable or a refused keyring means the backend is unusable.
        try {
          await run('secret-tool', ['search', ...KEYRING_ATTRIBUTES])
          return true
        } catch {
          return false
        }
      }
      return true
    },
    async sealBytes(bytes) {
      await run('secret-tool', ['store', '--label', 'DSH credential store data key', ...KEYRING_ATTRIBUTES], bytes)
      return bytes
    },
    async unsealBytes(blob) {
      const value = await run('secret-tool', ['lookup', ...KEYRING_ATTRIBUTES], blob)
      // The keyring holds the value verbatim; when it is absent the lookup is
      // empty, which is a miss the caller must see as a failure to unwrap.
      if (value.length === 0) throw new Error('secret-service: the data key is not in the keyring')
      return value
    },
  }

  return { tpm2, secretService }
}
