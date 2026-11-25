import { SetMetadata } from "@nestjs/common";

/**
 * Metadata key used to mark a route or controller as public.
 * Set by {@link SkipBasicAuth} and read by `BasicAuthGuard`.
 */
export const SKIP_BASIC_AUTH_KEY = "nestjs-basic-auth:skip";

/**
 * Marks a route handler or controller as public: `BasicAuthGuard` skips all
 * Basic auth checks for it, so no credentials are required and `req.user` is
 * left untouched.
 *
 * Works with global guards (`app.useGlobalGuards(new BasicAuthGuard())`),
 * per-route guards (`@UseGuards(...)`), and guards provided through
 * `BasicAuthModule.forRoot()` — the decorators only need Nest's metadata, not
 * dependency injection.
 *
 * Method-level metadata takes precedence over class-level metadata, so a
 * protected route inside a public controller can opt back in by setting the
 * key to `false` with `SetMetadata(SKIP_BASIC_AUTH_KEY, false)`.
 *
 * @example
 * ```ts
 * import { Controller, Get } from "@nestjs/common";
 * import { SkipBasicAuth } from "nestjs-basic-auth";
 *
 * @Controller("health")
 * export class HealthController {
 *   @Get()
 *   @SkipBasicAuth()
 *   check(): string {
 *     return "ok";
 *   }
 * }
 * ```
 */
export const SkipBasicAuth = () => SetMetadata(SKIP_BASIC_AUTH_KEY, true);
