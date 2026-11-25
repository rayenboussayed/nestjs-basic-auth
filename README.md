# nestjs-basic-auth

Minimal, secure NestJS Basic auth module wrapping the [`basic-auth`](https://www.npmjs.com/package/basic-auth) npm package.

## Installation

```sh
npm install nestjs-basic-auth basic-auth @nestjs/common
```

`@nestjs/core` is a runtime dependency (the guard uses its `Reflector`); `@nestjs/platform-express` is a dev dependency used by the tests, which start a real HTTP server. Install your preferred HTTP platform at runtime for the app itself.

## Quick start

Environment-based (default) — set `AUTH_NAME` and `AUTH_PASS`:

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

### Public routes with `@SkipBasicAuth()`

Routes that must answer without credentials (health checks, webhooks) can opt out of the guard:

```ts
import { Controller, Get } from "@nestjs/common";
import { SkipBasicAuth } from "nestjs-basic-auth";

@Controller("health")
export class HealthController {
  @Get()
  @SkipBasicAuth()
  check(): string {
    return "ok";
  }
}
```

Put `@SkipBasicAuth()` on a controller to make all of its routes public. The decorator works with global guards, per-route guards, and guards provided by `BasicAuthModule.forRoot()` — it only needs Nest metadata, not dependency injection.

## API reference

### `BasicAuthGuard`

- Implements NestJS `CanActivate`; apply globally with `app.useGlobalGuards(new BasicAuthGuard(options?))` or per route with `@UseGuards(new BasicAuthGuard(options?))`.
- On success: sets `req.user` to the validated credentials (the package's `Credentials`).
- On failure (missing/invalid header or wrong credentials): sets `WWW-Authenticate` on the response and throws `UnauthorizedException` (401).

Constructor options:

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `credentials` | `Credentials \| Credentials[]` | `environment` (`AUTH_NAME`/`AUTH_PASS`) | Credentials accepted by the guard: one pair or a list. |
| `realm` | `string` | `environment.AUTH_REALM`, then `"Secure Area"` | Realm included in the `WWW-Authenticate: Basic realm="..."` challenge. |
| `header` | `string` | `"authorization"` | Name of the request header carrying the credentials. |
| `headerNames` | `{ name: string; pass: string }` | `{ name: "x-auth-name", pass: "x-auth-pass" }` | Header names for the fallback credentials; both string values must be present. |
| `body` | `boolean` | `false` | Accept credentials from `body.auth.name` / `body.auth.pass` when the header yields none. |

### `BasicAuthModule`

- `BasicAuthModule.forRoot(options?: BasicAuthOptions)` — registers the options token and provides/exports `BasicAuthGuard` with those options.

### `SkipBasicAuth`

- `SkipBasicAuth()` — decorator for route handlers or controllers; the guard skips Basic auth for marked routes.
- `SKIP_BASIC_AUTH_KEY` — exported metadata key (`"nestjs-basic-auth:skip"`), useful for reads via `Reflector` or for opting back in with `SetMetadata(SKIP_BASIC_AUTH_KEY, false)`.
- Handler-level metadata wins over controller-level metadata, so a single route in a public controller can be protected again by setting the key to `false`.

### Types

- `Credentials` — re-exported from the `basic-auth` package: `{ name: string; pass: string }`.

## Generated API docs

A generated, per-file version of this reference lives in [`docs/`](./docs):

- [`docs/basic-auth.guard.md`](./docs/basic-auth.guard.md) — `BasicAuthGuard`, credential resolution, and comparison.
- [`docs/basic-auth.module.md`](./docs/basic-auth.module.md) — `BasicAuthModule.forRoot()`.
- [`docs/skip-basic-auth.decorator.md`](./docs/skip-basic-auth.decorator.md) — `SkipBasicAuth` and its metadata key.

These pages are generated from the JSDoc in [`src/`](./src) by [mdaics](https://github.com/rayenboussayed/mdaics) and are committed — regenerate them with `npm run docs` instead of editing them by hand. Every documented symbol ends with `src:`/`dist:` pointer lines (file and line in the source and built output). Parameter types in the generated tables are resolved by the TypeScript compiler at generation time.

## Behavior notes (from `basic-auth@3.1.0`)

- Credentials are resolved in order: (1) the `authorization` header via `parse()` when the header is present; (2) the custom `headerNames` headers when both values are strings; (3) the body pair when `body: true`. If the standard header is present but malformed, the request is rejected.
- `parse(header)` returns `{ name, pass }` on success, `undefined` when missing or malformed (e.g. wrong scheme, invalid base64, or no colon in the decoded value).
- Comparison is constant-time (`timingSafeEqual` in `src/basic-auth.guard.ts`).
- Routes decorated with `@SkipBasicAuth()` bypass the guard: `canActivate` returns `true` before any credential resolution, leaves `req.user` untouched, and emits no `WWW-Authenticate`.
- Basic sends credentials base64-encoded — use HTTPS.

## Security notes

- Failure responses are a 401 with an escaped `WWW-Authenticate: Basic realm="..."` challenge.
- Credentials are hashed with SHA-256 to fixed-length digests and compared with `timingSafeEqual` against all configured credentials without short-circuit (`src/basic-auth.guard.ts`) — response timing reveals neither valid names nor the expected pass lengths.
- Body credentials travel in the request body rather than the standard challenge mechanism — use HTTPS/TLS and avoid logging request bodies.
- Custom `headerNames` act as alternative credential carriers — treat them with the same secrecy as `Authorization`; avoid logging or proxying them, and restrict them to TLS.
- Enabling `headerNames`/`body` broadens where credentials can leak (logs, caches, intermediaries) — pair with HTTPS and rate limiting.
- Only apply `@SkipBasicAuth()` to routes intended to be public: skipped routes perform no authentication and set no `req.user`, so downstream code must not assume an authenticated principal there.

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

- `test/unit` — guard behavior (parse, realm, credentials lists, custom header), `@SkipBasicAuth` metadata semantics, `parse` of the package, environment schema.
- `test/integration` — `Test.createTestingModule` wiring via `BasicAuthModule.forRoot()`, including skip metadata on the DI-provided guard.
- `test/e2e` — real server + global `fetch`: 401 + `WWW-Authenticate` on failure, 200 on success, 401 on wrong credentials, public routes via `@SkipBasicAuth()`.
- `test/perf` — micro-benchmarks: package `parse`, `timingSafeEqual` (node:crypto), the full guard paths — standard header, custom headers, and body (`node:perf_hooks`).
- `test/memory` — heap usage across repeated guard calls (run with `NODE_OPTIONS=--expose-gc` for real GC; the `test:memory` script does this).
