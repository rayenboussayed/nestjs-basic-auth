# nestjs-basic-auth

Minimal, secure NestJS Basic auth module wrapping the [`basic-auth`](https://www.npmjs.com/package/basic-auth) npm package.

## Installation

```sh
npm install nestjs-basic-auth basic-auth @nestjs/common
```

`@nestjs/core` and `@nestjs/platform-express` are dev dependencies of this repo (used by the tests, which start a real HTTP server); install your preferred HTTP platform at runtime for the app itself.

## Quick start

Environment-based (default) — set `AUTH_USERNAME` and `AUTH_PASSWORD`:

```ts
// app.module.ts
import { Module } from "@nestjs/common";
import { BasicAuthModule } from "nestjs-basic-auth";

@Module({
  imports: [BasicAuthModule.forRoot()],
})
export class AppModule {}

// main.ts
import { BasicAuthGuard } from "nestjs-basic-auth";

app.useGlobalGuards(new BasicAuthGuard());
```

Options-based — pass credentials, realm or header on the guard instance:

```ts
import { NestFactory } from "@nestjs/core";
import { BasicAuthGuard, BasicAuthModule } from "nestjs-basic-auth";

@Module({
  imports: [BasicAuthModule.forRoot()],
})
class AppModule {}

app.useGlobalGuards(
  new BasicAuthGuard({
    realm: "app",
    credentials: [{ name: "admin", pass: "s3cret" }],
  }),
);
```

The same instance works per route: `@UseGuards(new BasicAuthGuard({...}))`.

## API reference

### `BasicAuthGuard`

- Implements NestJS `CanActivate`; apply globally with `app.useGlobalGuards(new BasicAuthGuard(options?))` or per route with `@UseGuards(new BasicAuthGuard(options?))`.
- On success: sets `req.user` to the validated credentials (the package's `Credentials`).
- On failure (missing/invalid header or wrong credentials): sets `WWW-Authenticate` on the response and throws `UnauthorizedException` (401).

Constructor options:

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `credentials` | `Credentials \| Credentials[]` | `environment` (`AUTH_USERNAME`/`AUTH_PASSWORD`) | Credentials accepted by the guard: one pair or a list. |
| `realm` | `string` | `environment.AUTH_REALM`, then `"Secure Area"` | Realm included in the `WWW-Authenticate: Basic realm="..."` challenge. |
| `header` | `string` | `"authorization"` | Name of the request header carrying the credentials. |
| `headerNames` | `{ username: string; password: string }` | `{ username: "x-auth-username", password: "x-auth-password" }` | Header names for the fallback credentials; both string values must be present. |
| `body` | `boolean` | `false` | Accept credentials from `body.auth.username` / `body.auth.password` when the header yields none. |

### `BasicAuthModule`

- `BasicAuthModule.forRoot(options?: BasicAuthOptions): DynamicModule` — provides the guard via `useFactory`, so the guard carries the `forRoot` options.

### Types

- `Credentials` — re-exported from the `basic-auth` package: `{ name: string; pass: string }`.

## Generated API docs

A generated, per-file version of this reference lives in [`docs/`](./docs):

- [`docs/basic-auth.guard.md`](./docs/basic-auth.guard.md) — `BasicAuthGuard`, credential resolution, and comparison.
- [`docs/basic-auth.module.md`](./docs/basic-auth.module.md) — `BasicAuthModule.forRoot()`.

These pages are generated from the JSDoc in [`src/`](./src) by [mdaics](https://github.com/rayenboussayed/mdaics) and are committed — regenerate them with `npm run docs` instead of editing them by hand. Every documented symbol ends with `src:`/`dist:` pointer lines (file and line in the source and built output). Parameter types in the generated tables are resolved by the TypeScript compiler at generation time.

## Behavior notes (from `basic-auth@3.1.0`)

- Credentials are resolved in order: (1) the `authorization` header via `parse()` when the header is present; (2) the custom `headerNames` headers when both values are strings; (3) the body pair when `body: true`. If the standard header is present but malformed, the request is rejected.
- `parse(header)` returns `{ name, pass }` on success, `undefined` when missing or malformed (e.g. wrong scheme, invalid base64, or no colon in the decoded value).
- Comparison is constant-time (`timingSafeEqual` in `src/basic-auth.guard.ts`).
- Basic sends credentials base64-encoded — use HTTPS.

## Security notes

- Failure responses are a 401 with an escaped `WWW-Authenticate: Basic realm="..."` challenge.
- Constants are compared against all configured credentials without short-circuit and with length-padded buffers (`timingSafeEqual` in `src/basic-auth.guard.ts`) — response timing reveals neither valid usernames nor the expected password lengths.
- Body credentials travel in the request body rather than the standard challenge mechanism — use HTTPS/TLS and avoid logging request bodies.
- Custom `headerNames` act as alternative credential carriers — treat them with the same secrecy as `Authorization`; avoid logging or proxying them, and restrict them to TLS.
- Enabling `headerNames`/`body` broadens where credentials can leak (logs, caches, intermediaries) — pair with HTTPS and rate limiting.
- `options.credentials` entries are validated at construction (zod schema in `src/basic-auth.guard.ts`); invalid entries throw immediately instead of failing with a 500 on the first request.

## Development

```sh
npm run check            # typecheck + build + tests
npm run typecheck
npm run build
npm run docs             # rebuild + regenerate API markdown in docs/
npm run test             # unit + integration + e2e
npm run test:unit
npm run test:integration
npm run test:e2e
npm run test:perf
npm run test:memory
npm run test:coverage
```

`npm run docs` runs [mdaics](https://github.com/rayenboussayed/mdaics): it writes one Markdown page per documented source file into `docs/` and appends `src:`/`dist:` line pointers to each symbol. The script builds `dist/` first so those pointers reference real built lines; `sourceMap: true` makes them exact. Generated pages are overwritten on every run — change JSDoc in `src/`, never the markdown. Docs generation is not part of `npm run check`.

## Testing

- `test/unit` — guard behavior (parse, realm, credentials lists, custom header), `parse` of the package, environment schema.
- `test/integration` — `Test.createTestingModule` wiring via `BasicAuthModule.forRoot()`.
- `test/e2e` — real server + global `fetch`: 401 + `WWW-Authenticate` on failure, 200 on success, 401 on wrong credentials.
- `test/perf` — micro-benchmarks: package `parse`, `timingSafeEqual` (node:crypto), the full guard paths — standard header, custom headers, and body (`node:perf_hooks`).
- `test/memory` — heap usage across repeated guard calls (run with `NODE_OPTIONS=--expose-gc` for real GC; the `test:memory` script does this).
