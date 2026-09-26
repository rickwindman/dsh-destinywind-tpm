/**
 * Envelope encryption for stored credentials: one AES-256-GCM data key per
 * store, itself sealed by the platform key protector, and one authenticated
 * ciphertext per value.
 *
 * The indirection exists because a platform protector call is expensive — on
 * Windows a DPAPI call is a process spawn — while a credential store performs
 * many reads and writes per session. Sealing only the data key keeps the
 * expensive operation to once per store lifetime and every payload in-process,
 * without weakening the property that matters: without the OS user's own
 * credential the data key cannot be recovered, and every ciphertext is bound to
 * its own address, so a value cannot be moved between references undetected.
 *
 * Each ciphertext carries a fresh random 12-byte nonce and a 16-byte tag, and
 * authenticates the address it was written for as additional data.
 * @module dsh-destinywind-tpm/envelope
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'

/** AES-256-GCM nonce length in bytes. */
const IV_LENGTH = 12

/** AES-256-GCM authentication tag length in bytes. */
const TAG_LENGTH = 16

/** Data key length in bytes. */
export const KEY_LENGTH = 32

/** Generate one fresh data key. */
export function createDataKey() {
  return randomBytes(KEY_LENGTH)
}

/**
 * Seal one plaintext for one address.
 * @param {Buffer} key - the store's data key.
 * @param {string} address - the reference name or record key this value belongs to.
 * @param {string} plaintext - the value to protect.
 * @returns {string} base64 of nonce ‖ tag ‖ ciphertext.
 */
export function sealValue(key, address, plaintext) {
  const nonce = randomBytes(IV_LENGTH)
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_LENGTH })
  cipher.setAAD(Buffer.from(address, 'utf8'))
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  return Buffer.concat([nonce, cipher.getAuthTag(), body]).toString('base64')
}

/**
 * Unseal one value written by {@link sealValue} for the same address.
 * @param {Buffer} key - the store's data key.
 * @param {string} address - the address the value was sealed for.
 * @param {string} sealed - base64 produced by {@link sealValue}.
 * @returns {string} the plaintext.
 */
export function unsealValue(key, address, sealed) {
  const raw = Buffer.from(sealed, 'base64')
  if (raw.length < IV_LENGTH + TAG_LENGTH) {
    throw new Error(`destinywind-tpm: sealed value for "${address}" is truncated`)
  }
  const nonce = raw.subarray(0, IV_LENGTH)
  const tag = raw.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH)
  const body = raw.subarray(IV_LENGTH + TAG_LENGTH)
  const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_LENGTH })
  decipher.setAAD(Buffer.from(address, 'utf8'))
  decipher.setAuthTag(tag)
  try {
    return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8')
  } catch {
    // GCM refuses to decrypt anything not sealed for this address with this key,
    // so the honest report is that the value is unreadable, not merely wrong.
    throw new Error(
      `destinywind-tpm: the value for "${address}" failed authentication; it was sealed by another `
      + 'Windows user or machine, or the store was modified outside this provider',
    )
  }
}
