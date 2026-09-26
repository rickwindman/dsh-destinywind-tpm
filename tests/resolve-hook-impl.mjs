/**
 * The resolution hook body: make bare `@deepseek-ai/*` specifiers resolve
 * outside the harness exactly as they do inside it.
 *
 * Inside the harness, an import of `@deepseek-ai/*` from a profile plugin is
 * not resolved by Node at all: it is intercepted and routed to the installation
 * that declared the package. Outside it those imports fail, so a plugin cannot
 * be exercised from a bare `node` invocation.
 *
 * The hook defers to Node first and only intervenes when native resolution
 * fails, so every transitive dependency of a real package — the target's own
 * `node_modules`, its `exports` map, conditional entries — is resolved by Node
 * itself and cannot be papered over. When native resolution does fail, the
 * specifier is looked up in the harness's own installation table (the same
 * 568-entry map the running process uses) and retried from a parent directory
 * positioned to reach that exact installation.
 * @module dsh-destinywind-tpm/tests/resolve-hook-impl
 */

import { dirname, join } from 'node:path'
import { realpathSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const { createRuntimeResolution } = await import('file:///D:/dsh/packages/boot/app-boot/lib/index.js')

/** The installation map, keyed by package name. */
const entries = new Map()
const resolution = await createRuntimeResolution({ installAnchor: 'D:/dsh/apps/cli/package.json' })
for (const entry of resolution.entries) {
  // First declaration wins, matching the order the resolver itself uses.
  if (!entries.has(entry.name)) entries.set(entry.name, entry.packageDir)
}

/**
 * Parent directories from which native lookup reaches `packageDir`.
 *
 * A package lives at `<root>/node_modules/<name>`, and Node finds it by walking
 * up from the importing file to the nearest `node_modules`. The parent file
 * therefore has to sit inside `root` — the directory owning that
 * `node_modules` — and `root` is whatever precedes the last `node_modules`
 * segment of the package's own path. Ancestors of `root` are offered as well,
 * so a hoisted installation reachable from a higher directory still resolves.
 * @param {string} packageDir - the directory the resolution table named.
 * @returns {string[]} candidate parent file paths, nearest first.
 */
function candidatesFor(packageDir) {
  const segments = packageDir.split(/[\\/]/)
  const lastModules = segments.lastIndexOf('node_modules')
  if (lastModules < 1) return []
  const candidates = []
  let root = segments.slice(0, lastModules).join('\\')
  for (let depth = 0; depth < 3; depth += 1) {
    candidates.push(join(root, '__dsh_resolve__.js'))
    const parent = dirname(root)
    if (parent === root) break
    root = parent
  }
  return candidates
}

/**
 * Retry one specifier from each parent that can reach its declared installation.
 * @param {string} specifier - the import specifier as written.
 * @param {object} context - Node's resolution context.
 * @param {Function} nextResolve - Node's own resolver.
 * @returns {Promise<object | undefined>} the resolution, or undefined when no candidate reaches it.
 */
async function resolveThroughTable(specifier, context, nextResolve) {
  const parts = specifier.split('/')
  const name = specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0]
  const packageDir = entries.get(name)
  if (packageDir === undefined) return undefined
  // The table records the junction a workspace link created, while Node reports
  // the real path it resolved through, so the two only compare after realpath.
  const expected = realpathSync(packageDir).replaceAll('\\', '/').toLowerCase()
  for (const parent of candidatesFor(packageDir)) {
    try {
      const resolved = await nextResolve(specifier, { ...context, parentURL: pathToFileURL(parent).href })
      // Only a hit inside the declared installation is representative; a
      // different copy would make the test prove the wrong thing.
      const actual = realpathSync(new URL(resolved.url)).replaceAll('\\', '/').toLowerCase()
      if (actual.startsWith(expected)) return resolved
    } catch {
      // This candidate cannot see the package; try the next ancestor.
    }
  }
  return undefined
}

/** Node's resolver hook. */
export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context)
  } catch (error) {
    const isBare = !specifier.startsWith('.') && !specifier.startsWith('node:')
      && !specifier.startsWith('file:') && !specifier.startsWith('data:')
    if (!isBare) throw error
    const resolved = await resolveThroughTable(specifier, context, nextResolve)
    if (resolved === undefined) throw error
    return resolved
  }
}
