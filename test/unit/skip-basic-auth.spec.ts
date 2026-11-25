import "reflect-metadata";
import { describe, expect, it } from "vitest";
import { SetMetadata, UnauthorizedException } from "@nestjs/common";
import type { ExecutionContext } from "@nestjs/common";
import { BasicAuthGuard } from "../../src/basic-auth.guard.js";
import { SKIP_BASIC_AUTH_KEY, SkipBasicAuth } from "../../src/skip-basic-auth.decorator.js";

class PublicMethodController {
  @SkipBasicAuth()
  publicRoute() {}

  protectedRoute() {}
}

@SkipBasicAuth()
class PublicClassController {
  protectedRoute() {}
}

class OptBackInController {
  @SetMetadata(SKIP_BASIC_AUTH_KEY, false)
  protectedRoute() {}
}

interface TestRequest {
  headers: Record<string, string>;
  user?: unknown;
}

/** A context with metadata-aware handler/class accessors and a real request object. */
function context(handler?: object, controller?: object) {
  const request: TestRequest = { headers: {} };
  return {
    request,
    context: {
      switchToHttp: () => ({ getRequest: () => request, getResponse: () => ({}), getNext: () => ({}) }),
      getHandler: () => handler,
      getClass: () => controller,
    } as unknown as ExecutionContext,
  };
}

const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" } });

describe("SkipBasicAuth", () => {
  it("sets the metadata key to true on both methods and classes", () => {
    expect(Reflect.getMetadata(SKIP_BASIC_AUTH_KEY, PublicMethodController.prototype.publicRoute)).toBe(true);
    expect(Reflect.getMetadata(SKIP_BASIC_AUTH_KEY, PublicClassController)).toBe(true);
  });

  it("skips auth for a decorated handler without resolving credentials or setting req.user", () => {
    const { context: ctx, request } = context(PublicMethodController.prototype.publicRoute, PublicMethodController);
    expect(guard.canActivate(ctx)).toBe(true);
    expect(request.user).toBeUndefined();
  });

  it("skips auth for a decorated controller", () => {
    const { context: ctx } = context(PublicClassController.prototype.protectedRoute, PublicClassController);
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it("still enforces auth on an undecorated handler in an undecorated controller", () => {
    const { context: ctx } = context(PublicMethodController.prototype.protectedRoute, PublicMethodController);
    expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
  });

  it("lets handler-level false override class-level true", () => {
    const { context: ctx } = context(OptBackInController.prototype.protectedRoute, PublicClassController);
    expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
  });

  it("skips auth even when the request carries credentials", () => {
    const { context: ctx, request } = context(PublicMethodController.prototype.publicRoute, PublicMethodController);
    const basic = `Basic ${Buffer.from("u:p").toString("base64")}`;
    request.headers.authorization = basic;
    expect(guard.canActivate(ctx)).toBe(true);
    expect(request.user).toBeUndefined();
  });

  it("keeps enforcing auth when the context has no getHandler/getClass (backward compatibility)", () => {
    const request: TestRequest = { headers: {} };
    const ctx = {
      switchToHttp: () => ({ getRequest: () => request, getResponse: () => ({}), getNext: () => ({}) }),
    } as unknown as ExecutionContext;
    expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
  });
});
