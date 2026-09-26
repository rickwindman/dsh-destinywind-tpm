/**
 * Choose and use the strongest key protector this machine actually has.
 *
 * Every platform exposes a different API for the same idea — a key held by the
 * machine rather than by the process — and a machine without the hardware for
 * the strongest one still has something better than a plaintext file. This
 * module is the single place that decides which is used, in this order:
 *
 *   1. a TPM-resident key (Windows CNG Platform Crypto Provider, or tpm2-tools
 *      on Linux): the store is unreadable off this exact machine.
 *   2. the OS user's own secret store (Windows DPAPI, or the session keyring on
 *      Linux): bound to the signed-in user, readable on the same machine by that
 *      user alone, and never written in the clear.
 *
 * A protector is used only after it proves a full wrap/unwrap round trip, so a
 * machine whose TPM answers but mangles data falls through to the next one
 * rather than sealing a store it cannot later read. When nothing answers the
 * provider refuses to mount, because the alternative is the plaintext file this
 * plugin exists to replace.
 * @module dsh-destinywind-tpm/protector
 */

import { dpapiAvailable, sealBytes as dpapiSeal, unsealBytes as dpapiUnseal } from './dpapi.js'
import { linuxProtectors } from './linux.js'
import { sealBytes as tpmSeal, tpmAvailable, unsealBytes as tpmUnseal } from './tpm.js'

/** How the current store's data key is wrapped. */
export const WRAP_TPM = 'tpm'
export const WRAP_USER = 'user'

/**
 * Wrap and unwrap a payload with one concrete protector.
 * @typedef {object} Protector
 * @property {string} wrap - one of {@link WRAP_TPM} or {@link WRAP_USER}.
 * @property {string} label - human-readable name for logs.
 * @property {(bytes: Buffer) => Promise<Buffer>} seal - wrap the payload.
 * @property {(blob: Buffer) => Promise<Buffer>} unseal - unwrap it again.
 */

/** Wrap one backend as a named protector. */
function asProtector(wrap, label, seal, unseal) {
  return { wrap, label, seal, unseal }
}

/**
 * The candidates for this platform, strongest first, each with its own proof.
 * @returns {Promise<{wrap: string, label: string, available: () => Promise<boolean>, make: () => Protector}[]>}
 */
function candidates() {
  if (process.platform === 'win32') {
    return [
      { wrap: WRAP_TPM, label: 'TPM (CNG Platform Crypto Provider)', available: tpmAvailable, make: () => asProtector(WRAP_TPM, 'TPM', tpmSeal, tpmUnseal) },
      { wrap: WRAP_USER, label: 'DPAPI (current Windows user)', available: dpapiAvailable, make: () => asProtector(WRAP_USER, 'DPAPI', dpapiSeal, dpapiUnseal) },
    ]
  }
  const { tpm2, secretService } = linuxProtectors()
  return [
    { wrap: WRAP_TPM, label: 'TPM 2.0 (tpm2-tools)', available: tpm2.available, make: () => asProtector(WRAP_TPM, 'TPM', tpm2.sealBytes, tpm2.unsealBytes) },
    { wrap: WRAP_USER, label: 'session keyring (libsecret)', available: secretService.available, make: () => asProtector(WRAP_USER, 'keyring', secretService.sealBytes, secretService.unsealBytes) },
  ]
}

/** @type {Protector | undefined} the protector chosen for this process. */
let chosen

/** @type {Promise<Protector> | undefined} deduplicates concurrent selection. */
let pending

/**
 * The protector to use, chosen once per process.
 *
 * @param {(message: string) => void} [log] - diagnostic sink.
 * @returns {Promise<Protector>} the strongest protector that proved itself.
 * @throws {Error} when no protector on this machine can seal.
 */
export function selectProtector(log = () => {}) {
  if (chosen !== undefined) return Promise.resolve(chosen)
  if (pending !== undefined) return pending
  pending = (async () => {
    const failures = []
    for (const candidate of candidates()) {
      try {
        if (await candidate.available()) {
          chosen = candidate.make()
          log(`credentials-protector: using ${candidate.label}`)
          return chosen
        }
      } catch (error) {
        failures.push(`${candidate.label}: ${error instanceof Error ? error.message : String(error)}`)
      }
    }
    throw new Error(
      'credentials-protector: no key protector on this machine could wrap and unwrap a value, so credentials '
      + 'cannot be sealed; this provider refuses to store them in the clear'
      + (failures.length > 0 ? ` (${failures.join('; ')})` : ''),
    )
  })()
  pending.finally(() => { pending = undefined })
  return pending
}

/**
 * Unwrap a stored data key, using the protector its document names.
 *
 * The wrap is read from the store rather than re-selected, because a store
 * written on a machine with a TPM must stay readable on one without — and must
 * fail loudly rather than decrypt with the wrong protector, which GCM would
 * report as an authentication failure far from its real cause.
 * @param {string} wrap - the wrap recorded in the document.
 * @param {string} blob - base64 of the wrapped key.
 * @returns {Promise<Buffer>} the data key.
 */
export async function unwrapBy(wrap, blob) {
  const candidate = candidates().find(entry => entry.wrap === wrap)
  if (candidate === undefined) {
    throw new Error(`credentials-protector: unknown key wrap "${wrap}"`)
  }
  return await candidate.make().unseal(Buffer.from(blob, 'base64'))
}

/** Forget the cached choice; used by tests to force re-selection. */
export function resetProtector() {
  chosen = undefined
  pending = undefined
}
