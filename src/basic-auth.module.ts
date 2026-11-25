import { Module, type DynamicModule, type Provider } from "@nestjs/common";
import { BasicAuthGuard } from "./basic-auth.guard.js";
import type { BasicAuthOptions } from "./basic-auth.guard.js";

/**
 * Minimal NestJS module for the Basic auth guard.
 *
 * `forRoot(options?)` returns a `DynamicModule` that provides `BasicAuthGuard`
 * with the resolved options (via `useFactory`, so the guard carries them
 * regardless of how Nest instantiates it).
 */
@Module({})
export class BasicAuthModule {
  /**
   * Registers `BasicAuthGuard` as a provider carrying `options`.
   * @param options - Guard options; omitted values fall back to the environment/defaults.
   * @returns A `DynamicModule` exporting `BasicAuthGuard`.
   */
  static forRoot(options?: BasicAuthOptions): DynamicModule {
    const providers: Provider[] = [{ provide: BasicAuthGuard, useFactory: () => new BasicAuthGuard(options) }];
    return { module: BasicAuthModule, providers, exports: [BasicAuthGuard] };
  }
}
