import "reflect-metadata";
import { describe, expect, it } from "vitest";
import { UnauthorizedException } from "@nestjs/common";
import type { ExecutionContext } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import { BasicAuthGuard } from "../../src/basic-auth.guard.js";
import { BasicAuthModule } from "../../src/basic-auth.module.js";
import { SkipBasicAuth } from "../../src/skip-basic-auth.decorator.js";

class PublicController {
  @SkipBasicAuth()
  publicRoute() {}

  protectedRoute() {}
}

function context(handler: object, controller: object) {
  return {
    switchToHttp: () => ({ getRequest: () => ({ headers: {} }), getResponse: () => ({}), getNext: () => ({}) }),
    getHandler: () => handler,
    getClass: () => controller,
  } as unknown as ExecutionContext;
}

describe("SkipBasicAuth with the DI-provided guard", () => {
  it("honors skip metadata while still protecting other routes", async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [BasicAuthModule.forRoot({ credentials: { name: "u", pass: "p" } })],
    }).compile();
    const guard = moduleRef.get(BasicAuthGuard);

    expect(guard.canActivate(context(PublicController.prototype.publicRoute, PublicController))).toBe(true);
    expect(() => guard.canActivate(context(PublicController.prototype.protectedRoute, PublicController))).toThrow(
      UnauthorizedException,
    );
  });
});
