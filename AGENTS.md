# AGENTS.md

Standalone npm package, not a monorepo. Public API is `src/index.ts`; `dist/` is generated and gitignored. User-facing API docs live in `README.md`.

## Commands

- `npm run check` — typecheck + lint + build + unit/integration/e2e + `mdaics`. Husky pre-commit runs it; commit-msg enforces conventional commits. There are no CI workflows.
- `npm test` is only unit + integration + e2e. `test:perf`, `test:memory` (needs `--expose-gc`), and `test:coverage` are separate scripts.
- Focused runs: `npx vitest run test/unit/basic-auth.guard.spec.ts`, or add `-t "test name"` for one case.
- Node >=22.17 is required by `jutilities`/`mdaics`.

## Generated docs

- `npm run docs` = build + mdaics; it overwrites `docs/*.md` and `.mdaicscache`, both committed. Never hand-edit `docs/` — change JSDoc in `src/`.
- `check` also runs `mdaics`, so `.mdaicscache` timestamps change on every check; restore it when only `lastUsed` moved.
- mdaics skips files without JSDoc and fails with "jsdoc produced no renderable docs" if a file's only export is a class with no top-level doc comment.

## Code invariants

- Strict TS: `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`, `verbatimModuleSyntax`, legacy Nest decorators. Keep the explicit `reject(response): never` — TS does not infer `never` for throwing methods and `canActivate` needs it to narrow `credentials`.
- Credentials are `name`/`pass` everywhere: env `AUTH_NAME`/`AUTH_PASS`/`AUTH_REALM` (zod-parsed at import in `src/environment.ts`), `headerNames: { name, pass }` (defaults `x-auth-name`/`x-auth-pass`), and `body.auth.name`/`auth.pass` only when `body: true`. Do not reintroduce `username`/`password`.
- `@SkipBasicAuth()` uses `SKIP_BASIC_AUTH_KEY`; handler metadata wins over class metadata and explicit `false` opts back in. Skipped routes must not set `req.user` or emit `WWW-Authenticate`. Unit fake contexts without `getHandler`/`getClass` must stay protected.
- `Reflector` is imported from `@nestjs/core` (runtime dependency) but is `@Optional()` with a `new Reflector()` default so manual `new BasicAuthGuard()` works.
- `isEmptyString(undefined)` from `jutilities/is` returns `false` — check for `undefined` before calling `parse`. Avoid `jutilities/json` (its superjson handler uses `new Function`); use subpaths such as `jutilities/is`, `jutilities/to`, `jutilities/node/hash`.
- Node lowercases incoming headers; `readHeader` looks up the lowercase name.

## Tests and publishing

- e2e specs start a real Nest server on `127.0.0.1` with an ephemeral port and use global `fetch`; no fixtures or external services.
- Origin is SSH (`git@github.com:rayenboussayed/nestjs-basic-auth.git`), branch `main`.
