/**
 * A module-resolution hook that gives a test process the same package
 * resolution the harness gives its own plugins.
 *
 * Inside the harness, `@deepseek-ai/*` imports from a profile plugin are not
 * resolved by Node at all: they are intercepted and routed to the installation
 * that declared them. Outside it, those same imports fail, so a plugin cannot
 * be exercised from a bare `node` invocation.
 *
 * Rather than hand-maintaining a path table, this hook asks the harness's own
 * resolver for the installation map — the same 568-entry table the running
 * process uses — and rewrites bare specifiers through it. That keeps the test
 * honest: it fails on exactly the specifiers the harness would fail on.
 *
 * Usage: node --import ./tests/resolve-hook.mjs tests/offline.mjs
 * @module dsh-destinywind-tpm/tests/resolve-hook
 */

import { register } from 'node:module'

register(new URL('./resolve-hook-impl.mjs', import.meta.url))
