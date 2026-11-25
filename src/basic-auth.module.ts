import { Module } from "@nestjs/common";
import { BASIC_AUTH_OPTIONS, BasicAuthGuard } from "./basic-auth.guard.js";
import type { BasicAuthOptions } from "./basic-auth.guard.js";

/** NestJS module that provides and exports {@link BasicAuthGuard} configured by `forRoot()`. */
@Module({})
export class BasicAuthModule {
  /** Provides and exports `BasicAuthGuard` configured with `options`. */
  static forRoot(options: BasicAuthOptions = {}) {
    return {
      module: BasicAuthModule,
      providers: [
        { provide: BASIC_AUTH_OPTIONS, useValue: options },
        BasicAuthGuard,
      ],
      exports: [BASIC_AUTH_OPTIONS, BasicAuthGuard],
    };
  }
}
