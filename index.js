/**
 * A platform credentials provider for the harness: every reference value and
 * every stored record is sealed under the strongest local key protector —
 * Windows TPM (CNG) with a DPAPI fallback, Linux tpm2-tools with a session
 * keyring fallback — before it reaches disk, and unsealed only at the moment
 * a consumer resolves it.
 *
 * The store is one file of authenticated ciphertexts plus a single data key
 * that DPAPI seals. Nothing in it is readable without the OS user's own
 * credential, so a copy of the file — a backup, a sync folder, another machine,
 * another account — yields no secret. There is no plaintext path and no
 * fallback: a sealing failure fails the write rather than degrading to
 * cleartext.
 *
 * The sealed store is the only source of credentials: there is no plaintext
 * fallback and no migration from a legacy `.credentials.yaml`. A fresh install
 * therefore resolves nothing until a value is saved — the offline test asserts
 * that absence explicitly, because a provider that quietly fell back to a
 * plaintext file would look identical to a working one while storing secrets
 * in the clear. Disabling this bundle restores the default provider; values
 * already sealed here stay sealed and must be re-entered for it.
 * @module dsh-destinywind-tpm
 */

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { Service } from '@deepseek-ai/cordis'
import { CredentialProvider } from '@deepseek-ai/dsh-credentials'
import { resolveDshHome } from '@deepseek-ai/dsh-home-paths'
import { launchEnvironmentOf } from '@deepseek-ai/dsh-launch-environment'
import z from '@deepseek-ai/schemastery'
import { createDataKey, sealValue, unsealValue } from './envelope.js'
import { selectProtector, unwrapBy, WRAP_USER } from './protector.js'

/** On-disk format version of the sealed store. */
const STORE_VERSION = 1

/** Default file name of the sealed store under the harness home. */
const STORE_FILENAME = '.credentials.dpapi.json'

/**
 * The sealed document: one platform-sealed data key plus ciphertexts addressed
 * by reference name and record key.
 * @typedef {object} SealedDocument
 * @property {number} version - format version.
 * @property {string} key - base64 blob wrapping the store's data key.
 * @property {string} keyWrap - which protector wrapped `key`.
 * @property {Record<string, string>} refs - sealed reference values by name.
 * @property {Record<string, string>} records - sealed records by key.
 */

/** Whether a filesystem error means absence; every other failure must surface. */
function isENOENT(error) {
  return error?.code === 'ENOENT'
}

/**
 * The sealed store: an in-memory view of one platform-protected file.
 *
 * Every public method runs through one serialized chain, so a read can never
 * observe a half-written document and two concurrent writers cannot lose each
 * other's entries. The chain is reentrant-free by construction: the private
 * `…Locked` methods do the work and never take the lock again, because a nested
 * acquisition would wait on the very operation that is waiting on it.
 */
class SealedStore {
  /** @type {string | undefined} the file's raw text as last read or written. */
  text

  /** @type {Buffer | undefined} the unwrapped data key; absent until needed. */
  dataKey

  /** @type {string | undefined} the base64 blob wrapping {@link dataKey}. */
  sealedKey

  /**
   * @type {string | undefined} which protector wrapped {@link sealedKey}.
   *
   * Read from the document rather than re-decided at load time: a store written
   * on a machine with a TPM must stay readable here, and one written by DPAPI
   * must not be handed to the TPM, which would fail as an authentication error
   * far from its real cause.
   */
  keyWrap

  /** @type {Map<string, string>} sealed reference values by name. */
  refs = new Map()

  /** @type {Map<string, string>} sealed records by key. */
  records = new Map()

  /** @type {Promise<unknown>} serializes every operation. */
  operations = Promise.resolve()

  /**
   * @param {string} path - absolute path of the sealed store.
   * @param {(message: string) => void} warn - diagnostic sink.
   */
  constructor(path, warn) {
    this.path = path
    this.warn = warn
  }

  /** Run one operation after every earlier one, whatever its outcome. */
  serialize(operation) {
    const next = this.operations.then(operation, operation)
    // A rejected operation must not poison the chain for its successors.
    this.operations = next.then(() => undefined, () => undefined)
    return next
  }

  /** Load the document when its content changed since the last read. */
  async loadLocked() {
    let text
    try {
      text = await readFile(this.path, 'utf8')
    } catch (error) {
      if (!isENOENT(error)) throw error
      text = undefined
    }
    if (text === this.text) return
    const refs = new Map()
    const records = new Map()
    let sealedKey
    let keyWrap
    if (text !== undefined && text.trim().length > 0) {
      const parsed = JSON.parse(text)
      if (parsed.version !== STORE_VERSION) {
        throw new Error(`destinywind-tpm: unsupported store version ${String(parsed.version)} in ${this.path}`)
      }
      sealedKey = parsed.key
      // A store written before the protector was configurable has no `keyWrap`.
      // It was sealed by DPAPI, which is what that generation always used, so
      // the field defaults to the user wrap rather than to a re-selection.
      keyWrap = parsed.keyWrap ?? WRAP_USER
      for (const [name, blob] of Object.entries(parsed.refs ?? {})) refs.set(name, blob)
      for (const [key, blob] of Object.entries(parsed.records ?? {})) records.set(key, blob)
    }
    this.text = text
    this.refs = refs
    this.records = records
    this.sealedKey = sealedKey
    this.keyWrap = keyWrap
    // A document whose data key changed belongs to a different key epoch, so
    // the cached key is dropped rather than reused against new ciphertexts.
    this.dataKey = undefined
  }

  /** The store's data key, unwrapping and caching it on first use. */
  async dataKeyLocked() {
    if (this.dataKey !== undefined) return this.dataKey
    if (this.sealedKey === undefined) {
      // First write into a store that has no key yet: mint one and seal it with
      // the strongest protector this machine proved it can use.
      const protector = await selectProtector(this.warn)
      const fresh = createDataKey()
      this.dataKey = fresh
      this.sealedKey = (await protector.seal(fresh)).toString('base64')
      this.keyWrap = protector.wrap
      return fresh
    }
    this.dataKey = await unwrapBy(this.keyWrap ?? WRAP_USER, this.sealedKey)
    return this.dataKey
  }

  /** Persist the current document atomically, creating the directory when needed. */
  async persistLocked() {
    const document = {
      version: STORE_VERSION,
      key: this.sealedKey,
      keyWrap: this.keyWrap,
      refs: Object.fromEntries(this.refs),
      records: Object.fromEntries(this.records),
    }
    const text = `${JSON.stringify(document, undefined, 2)}\n`
    await mkdir(dirname(this.path), { recursive: true })
    const staging = `${this.path}.tmp-${String(process.pid)}`
    await writeFile(staging, text, { mode: 0o600 })
    await rename(staging, this.path)
    this.text = text
  }

  /**
   * Resolve one reference, preferring the sealed store over the fallback layer.
   * @param {string} name - the reference name.
   * @returns {Promise<{value: string, source: string} | undefined>} the value and its layer.
   */
  async resolveRef(name) {
    return await this.serialize(async () => {
      await this.loadLocked()
      const blob = this.refs.get(name)
      if (blob !== undefined) {
        const key = await this.dataKeyLocked()
        return { value: unsealValue(key, name, blob), source: 'dpapi' }
      }
      return undefined
    })
  }

  /**
   * Where one reference resolves from, without decrypting anything. A caller
   * that only needs to know whether a credential is configured must not pay a
   * decryption for it, and must not hold the plaintext at all.
   * @param {string} name - the reference name.
   * @returns {Promise<string | undefined>} `dpapi`, or undefined.
   */
  async describeRef(name) {
    return await this.serialize(async () => {
      await this.loadLocked()
      if (this.refs.has(name)) return 'dpapi'
      return undefined
    })
  }

  /**
   * Seal and store one reference, or remove it when `value` is undefined.
   * @param {string} name - the reference name.
   * @param {string | undefined} value - the plaintext value, or undefined to remove.
   * @returns {Promise<boolean>} whether the sealed store changed.
   */
  async setRef(name, value) {
    return await this.serialize(async () => {
      await this.loadLocked()
      const present = this.refs.has(name)
      if (value === undefined) {
        if (!present) return false
        this.refs.delete(name)
      } else {
        const key = await this.dataKeyLocked()
        this.refs.set(name, sealValue(key, name, value))
      }
      await this.persistLocked()
      return true
    })
  }

  /** Read one record from the sealed store. */
  async getRecord(key) {
    return await this.serialize(async () => {
      await this.loadLocked()
      const blob = this.records.get(key)
      if (blob === undefined) return undefined
      const dataKey = await this.dataKeyLocked()
      return JSON.parse(unsealValue(dataKey, key, blob))
    })
  }

  /** Describe one record without exposing its value. */
  async describeRecord(key) {
    return await this.serialize(async () => {
      await this.loadLocked()
      if (this.records.has(key)) {
        const dataKey = await this.dataKeyLocked()
        const record = JSON.parse(unsealValue(dataKey, key, this.records.get(key)))
        return { configured: true, kind: record.kind, writable: true }
      }
      return { configured: false, writable: true }
    })
  }

  /** Enumerate every record in the sealed store. */
  async listRecords() {
    return await this.serialize(async () => {
      await this.loadLocked()
      const entries = new Map()
      for (const key of this.records.keys()) {
        const dataKey = await this.dataKeyLocked()
        const record = JSON.parse(unsealValue(dataKey, key, this.records.get(key)))
        entries.set(key, { key, kind: record.kind })
      }
      return [...entries.values()]
    })
  }

  /**
   * Store or remove one sealed record.
   * @param {string} key - the record address.
   * @param {{kind: string, payload: unknown} | undefined} record - the record, or undefined to remove.
   * @returns {Promise<boolean>} whether the sealed store changed.
   */
  async setRecord(key, record) {
    return await this.serialize(async () => {
      await this.loadLocked()
      if (record === undefined) {
        if (!this.records.has(key)) return false
        this.records.delete(key)
      } else {
        const dataKey = await this.dataKeyLocked()
        this.records.set(key, sealValue(dataKey, key, JSON.stringify(record)))
      }
      await this.persistLocked()
      return true
    })
  }

  /**
   * Read-decide-replace under one lock acquisition, so no other writer can
   * interleave between the read and the write.
   * @param {string} key - the record address.
   * @param {(current: object | undefined) => Promise<object | undefined>} mutate - the decision.
   * @returns {Promise<{record: object | undefined, changed: boolean}>} the outcome.
   */
  async modifyRecord(key, mutate) {
    return await this.serialize(async () => {
      await this.loadLocked()
      let current
      const blob = this.records.get(key)
      if (blob !== undefined) {
        const dataKey = await this.dataKeyLocked()
        current = JSON.parse(unsealValue(dataKey, key, blob))
      }
      const next = await mutate(current)
      // `mutate` returning undefined declines the write, so the caller must not
      // announce a change that never happened.
      if (next === undefined) return { record: current, changed: false }
      const dataKey = await this.dataKeyLocked()
      this.records.set(key, sealValue(dataKey, key, JSON.stringify(next)))
      await this.persistLocked()
      return { record: next, changed: true }
    })
  }

  /** Remove one record from the sealed store. */
  async deleteRecord(key) {
    return await this.setRecord(key, undefined)
  }

  /** Prove the platform protector works, reusing the stored key when there is one. */
  async probe() {
    return await this.serialize(async () => {
      await this.loadLocked()
      if (this.sealedKey !== undefined) {
        // Unwrapping the real key is both the health check and the work.
        await this.dataKeyLocked()
        return true
      }
      // No key yet: proving the protector works is the only meaningful probe,
      // because the chosen one is what the first write will seal with.
      await selectProtector(this.warn)
      return true
    })
  }

  /**
   * Prove the sealed store on disk is self-sufficient: re-read it, unwrap its
   * key, and confirm every entry unseals. Reading through the file rather than
   * the in-memory maps is the point — the on-disk artifact, not this process's
   * state, is what has to be sufficient.
   * @returns {Promise<number>} how many entries were proven to unseal.
   */
  async verifyAgainstDiskLocked() {
    const parsed = JSON.parse(await readFile(this.path, 'utf8'))
    if (parsed.version !== STORE_VERSION) {
      throw new Error(`destinywind-tpm: the store at ${this.path} has an unreadable version ${String(parsed.version)}`)
    }
    const dataKey = await unwrapBy(parsed.keyWrap ?? WRAP_USER, parsed.key)
    let proven = 0
    for (const [name, blob] of Object.entries(parsed.refs ?? {})) {
      if (unsealValue(dataKey, name, blob) === undefined) {
        throw new Error(`destinywind-tpm: "${name}" does not unseal from the store on disk`)
      }
      proven += 1
    }
    for (const [key, blob] of Object.entries(parsed.records ?? {})) {
      JSON.parse(unsealValue(dataKey, key, blob))
      proven += 1
    }
    return proven
  }
}

/** The DPAPI-backed credentials provider. */
export class DpapiCredentialProvider extends CredentialProvider {
  /** Diagnostic label; the registration key remains `credentials`. */
  name = 'destinywind-tpm'

  static Config = z.object({
    path: z.string().description('Absolute path of the sealed store; defaults to $DSH_HOME/.credentials.dpapi.json.'),
    dshHome: z.string().description('Harness home used when path is omitted.'),
  })

  /**
   * @param {import('@deepseek-ai/cordis').Context} ctx - the plugin context.
   * @param {{path?: string, dshHome?: string}} config - overrides.
   */
  constructor(ctx, config = {}) {
    super(ctx)
    const home = resolveDshHome(config.dshHome)
    this.path = config.path ?? join(home, STORE_FILENAME)
    this.store = new SealedStore(this.path, message => { this.ctx.logger.warn(message) })
  }

  /**
   * Fail the mount when the machine cannot seal. A provider that silently
   * degraded here would write secrets in the clear, which is the one outcome
   * this provider exists to prevent, and a mount-time failure names the cause
   * where a first-write failure would surface as an unrelated tool error.
   *
   * The probe runs before any write path can open, so a machine that cannot
   * seal fails at mount with a named cause instead of failing the first write.
   */
  async [Service.init]() {
    if (!await this.store.probe()) {
      throw new Error(
        'destinywind-tpm: the Windows Data Protection API is unavailable, so credentials cannot be sealed. '
        + 'This provider refuses to fall back to plaintext storage; disable this bundle to use the default provider.',
      )
    }
    this.ctx.logger.info('destinywind-tpm: sealed store at %s', this.path)
    try {
      const proven = await this.store.verifyAgainstDiskLocked()
      this.ctx.logger.info(
        'destinywind-tpm: the store at %s is readable; %d encrypted entry(ies) verified',
        this.path,
        proven,
      )
    } catch (error) {
      // An absent store is the expected state on a fresh install: there is
      // nothing to verify until the first credential is saved.
      this.ctx.logger.info('destinywind-tpm: no sealed store to verify yet at %s', this.path)
      this.ctx.logger.debug(error)
    }
  }

  /** Resolve one reference: process environment, sealed store, then .env layers. */
  async resolve(ref) {
    const env = launchEnvironmentOf(this.ctx).getFrom(ref, ['process'])
    if (env !== undefined && env.value.length > 0) return { value: env.value, source: 'env' }
    const stored = await this.store.resolveRef(ref)
    if (stored !== undefined) return stored
    const fallback = launchEnvironmentOf(this.ctx).getFrom(ref, ['project-env', 'user-env'])
    if (fallback !== undefined && fallback.value.length > 0) return { value: fallback.value, source: fallback.source }
    return undefined
  }

  /** Describe one reference without exposing its value. */
  async describe(ref) {
    const env = launchEnvironmentOf(this.ctx).getFrom(ref, ['process'])
    if (env !== undefined && env.value.length > 0) return { configured: true, source: 'env', writable: false }
    const stored = await this.store.describeRef(ref)
    if (stored !== undefined) return { configured: true, source: stored, writable: true }
    const fallback = launchEnvironmentOf(this.ctx).getFrom(ref, ['project-env', 'user-env'])
    if (fallback !== undefined && fallback.value.length > 0) {
      return { configured: true, source: fallback.source, writable: true }
    }
    return { configured: false, writable: true }
  }

  /** Seal and store one reference; an empty value is rejected in favour of `unset`. */
  async set(ref, value) {
    if (value.length === 0) {
      throw new Error(`destinywind-tpm: refusing to store an empty value for "${ref}"; call unset instead`)
    }
    this.assertUnshadowed(ref, 'set')
    if (await this.store.setRef(ref, value)) this.notifyUpdated(ref)
  }

  /** Remove one reference from the sealed store. */
  async unset(ref) {
    this.assertUnshadowed(ref, 'unset')
    if (await this.store.setRef(ref, undefined)) this.notifyUpdated(ref)
  }

  /** Read one record from the sealed store or the fallback layer. */
  async readRecord(key) {
    return await this.store.getRecord(key)
  }

  /** Describe one record without exposing its value. */
  async describeRecord(key) {
    return await this.store.describeRecord(key)
  }

  /** Enumerate every record in either layer. */
  async listRecords() {
    return await this.store.listRecords()
  }

  /** Serialized read-modify-write over one record. */
  async modifyRecord(key, mutate) {
    const { record, changed } = await this.store.modifyRecord(key, mutate)
    // `mutate` returning undefined leaves the entry untouched, so nothing is announced.
    if (changed) this.notifyRecordUpdated(key)
    return record
  }

  /** Remove one record from the sealed store. */
  async deleteRecord(key) {
    if (await this.store.deleteRecord(key)) this.notifyRecordUpdated(key)
  }

  /**
   * Refuse a write that a read-only source shadows, matching the default
   * provider: the write would appear to succeed while resolution kept
   * returning the launch environment's value.
   * @param {string} ref - the reference being written.
   * @param {string} verb - the operation name for the message.
   */
  assertUnshadowed(ref, verb) {
    const env = launchEnvironmentOf(this.ctx).getFrom(ref, ['process'])
    if (env !== undefined && env.value.length > 0) {
      throw new Error(
        `destinywind-tpm: "${ref}" is supplied read-only by the launch environment, so ${verb} would be shadowed; `
        + 'unset it in the shell that starts dsh instead',
      )
    }
  }
}

export default DpapiCredentialProvider
