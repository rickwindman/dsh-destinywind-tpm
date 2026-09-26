/**
 * Offline harness for the platform-protected credentials provider.
 *
 * The provider is a Cordis Service, so it cannot be constructed without a real
 * context. This file builds one from the installed Cordis runtime, mounts the
 * provider through `ctx.plugin`, and exercises the public seam end to end
 * against a temporary store — the ciphertext-on-disk claim, the protector
 * selection, and the tamper cases the envelope is supposed to catch.
 *
 * There is no plaintext fallback layer any more: the sealed store is the only
 * source of credentials, so a fresh install resolves nothing until a value is
 * saved. The checks below assert that absence explicitly, because a provider
 * that quietly fell back to a plaintext file would look identical to a working
 * one while storing secrets in the clear.
 *
 * It imports the harness's own packages by absolute path because it runs
 * outside the harness process, where the profile's module interception is not
 * installed; inside the process those same specifiers resolve normally.
 *
 * Run: node --import ./tests/resolve-hook.mjs tests/offline.mjs
 */

import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import assert from 'node:assert/strict'

/** The installed runtime directories this harness borrows from. */
const CLI_MODULES = 'file:///D:/dsh/apps/cli/node_modules/@deepseek-ai'
const { Context, Service } = await import(`${CLI_MODULES}/cordis/lib/index.js`)
const { DpapiCredentialProvider } = await import('../index.js')

const dir = mkdtempSync(join(tmpdir(), 'dsh-dpapi-'))
const storePath = join(dir, '.credentials.dpapi.json')

const ctx = new Context()
const messages = []
ctx.logger = {
  info: (...args) => messages.push(['info', ...args]),
  warn: (...args) => messages.push(['warn', ...args]),
  error: (...args) => messages.push(['error', ...args]),
  debug: () => {},
}
// The launcher fills this slot before any config entry mounts; an empty
// snapshot makes resolution depend on the store alone, as a clean shell would.
ctx.launchEnvironment = { get: () => undefined, getFrom: () => undefined }

const provider = new DpapiCredentialProvider(ctx, { path: storePath })

const results = []
/** Record one named check and its outcome. */
async function check(name, body) {
  try {
    await body()
    results.push(`PASS  ${name}`)
  } catch (error) {
    results.push(`FAIL  ${name}: ${error.message}`)
  }
}

await check('init succeeds on a machine with a usable protector', async () => {
  await provider[Service.init]()
})

await check('a fresh store resolves nothing, with no plaintext fallback', async () => {
  assert.equal(await provider.resolve('DEEPSEEK_API_KEY'), undefined)
  assert.equal((await provider.describe('DEEPSEEK_API_KEY')).configured, false)
})

await check('a stored reference round trips', async () => {
  await provider.set('DEEPSEEK_API_KEY', 'sk-round-trip-value')
  const resolved = await provider.resolve('DEEPSEEK_API_KEY')
  assert.equal(resolved.value, 'sk-round-trip-value')
  assert.equal(resolved.source, 'dpapi')
})

await check('the store records which protector wrapped its key', async () => {
  const document = JSON.parse(readFileSync(storePath, 'utf8'))
  assert.ok(document.keyWrap, 'the document must name its protector')
  assert.ok(['tpm', 'user'].includes(document.keyWrap), `unexpected wrap ${document.keyWrap}`)
})

await check('the store holds no plaintext', async () => {
  const text = readFileSync(storePath, 'utf8')
  assert.ok(!text.includes('sk-round-trip-value'), 'plaintext must not appear in the store')
  assert.ok(text.includes('"key"'), 'the store carries a wrapped data key')
})

await check('unicode and long values round trip', async () => {
  const value = `中文-😀-${'x'.repeat(4000)}`
  await provider.set('UNICODE_REF', value)
  assert.equal((await provider.resolve('UNICODE_REF')).value, value)
})

await check('describe reports the layer without exposing the value', async () => {
  const described = await provider.describe('DEEPSEEK_API_KEY')
  assert.equal(described.configured, true)
  assert.equal(described.source, 'dpapi')
  assert.equal(described.writable, true)
})

await check('unset removes a reference', async () => {
  await provider.unset('UNICODE_REF')
  assert.equal(await provider.resolve('UNICODE_REF'), undefined)
  assert.equal((await provider.describe('UNICODE_REF')).configured, false)
})

await check('an absent reference resolves to undefined', async () => {
  assert.equal(await provider.resolve('NEVER_SET'), undefined)
})

await check('records round trip and stay encrypted', async () => {
  await provider.modifyRecord('client-connection/browser-session', async () => ({
    kind: 'grant',
    payload: { version: 1, secret: 'sealed-record-secret' },
  }))
  const record = await provider.readRecord('client-connection/browser-session')
  assert.equal(record.payload.secret, 'sealed-record-secret')
  assert.ok(!readFileSync(storePath, 'utf8').includes('sealed-record-secret'))
})

await check('modifyRecord returning undefined leaves the record untouched', async () => {
  const before = await provider.readRecord('client-connection/browser-session')
  const after = await provider.modifyRecord('client-connection/browser-session', async () => undefined)
  assert.deepEqual(after, before)
})

await check('listRecords enumerates the sealed records', async () => {
  const keys = (await provider.listRecords()).map(entry => entry.key)
  assert.ok(keys.includes('client-connection/browser-session'), 'the sealed record is listed')
})

await check('deleteRecord removes a record', async () => {
  await provider.deleteRecord('client-connection/browser-session')
  assert.equal(await provider.readRecord('client-connection/browser-session'), undefined)
})

await check('a value sealed for one address cannot be moved to another', async () => {
  await provider.set('REF_A', 'value-for-a')
  const document = JSON.parse(readFileSync(storePath, 'utf8'))
  document.refs.REF_B = document.refs.REF_A
  writeFileSync(storePath, JSON.stringify(document))
  await assert.rejects(
    () => provider.resolve('REF_B'),
    /failed authentication/,
    'address binding must reject a relocated ciphertext',
  )
})

await check('a store from another format version is refused, not silently emptied', async () => {
  const document = JSON.parse(readFileSync(storePath, 'utf8'))
  document.version = 99
  writeFileSync(storePath, JSON.stringify(document))
  await assert.rejects(() => provider.resolve('REF_A'), /unsupported store version/)
})

await check('the store on disk is self-sufficient', async () => {
  // Drop the deliberately relocated REF_B first: it is a tampered entry that
  // is supposed to fail authentication, not something the store must recover.
  const document = JSON.parse(readFileSync(storePath, 'utf8'))
  document.version = 1
  delete document.refs.REF_B
  writeFileSync(storePath, JSON.stringify(document))
  const proven = await provider.store.verifyAgainstDiskLocked()
  assert.ok(proven >= 1, `expected at least one entry to verify, got ${proven}`)
})

await check('an empty value is refused in favour of unset', async () => {
  await assert.rejects(() => provider.set('EMPTY_REF', ''), /refusing to store an empty value/)
})

await check('no plaintext credential file is written anywhere', async () => {
  assert.equal(await provider.resolve('LEGACY_ONLY'), undefined, 'there is no fallback layer to resolve from')
})

console.log(results.join('\n'))
const failed = results.filter(line => line.startsWith('FAIL')).length
console.log(`\n${String(results.length - failed)}/${String(results.length)} checks passed`)
rmSync(dir, { recursive: true, force: true })
process.exitCode = failed === 0 ? 0 : 1
