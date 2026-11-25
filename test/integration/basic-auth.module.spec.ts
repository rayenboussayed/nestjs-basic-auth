import { describe, expect, it, vi } from "vitest";
import { UnauthorizedException } from "@nestjs/common";
import type { ExecutionContext } from "@nestjs/common";

async function importModules() {
  const { BasicAuthModule } = await import("../../src/basic-auth.module.js");
  const { BasicAuthGuard } = await import("../../src/basic-auth.guard.js");
  const { Test } = await import("@nestjs/testing");
  return { BasicAuthModule, BasicAuthGuard, Test };
}

function httpContext(headers: Record<string, string>) {
  return {
    switchToHttp: () => ({
      getRequest: () => ({ headers }),
      getResponse: () => ({}),
      getNext: () => ({}),
    }),
  } as unknown as ExecutionContext;
}

describe("BasicAuthModule", () => {
  it("provides BasicAuthGuard via forRoot()", async () => {
    const { BasicAuthModule, BasicAuthGuard, Test } = await importModules();
    const moduleRef = await Test.createTestingModule({
      imports: [BasicAuthModule.forRoot({ credentials: { name: "u", pass: "p" } })],
    }).compile();
    expect(moduleRef.get(BasicAuthGuard)).toBeInstanceOf(BasicAuthGuard);
  });

  it("returns the same guard instance on repeated resolution", async () => {
    const { BasicAuthModule, BasicAuthGuard, Test } = await importModules();
    const moduleRef = await Test.createTestingModule({
      imports: [BasicAuthModule.forRoot({ credentials: { name: "u", pass: "p" } })],
    }).compile();
    expect(moduleRef.get(BasicAuthGuard)).toBe(moduleRef.get(BasicAuthGuard));
  });

  it("resolves with env credentials when forRoot() is called without options", async () => {
    process.env.AUTH_NAME = "envuser";
    process.env.AUTH_PASS = "envpass";
    try {
      vi.resetModules();
      const { BasicAuthModule, BasicAuthGuard, Test } = await importModules();
      const moduleRef = await Test.createTestingModule({ imports: [BasicAuthModule.forRoot()] }).compile();
      expect(moduleRef.get(BasicAuthGuard)).toBeInstanceOf(BasicAuthGuard);
    } finally {
      delete process.env.AUTH_NAME;
      delete process.env.AUTH_PASS;
    }
  });

  it("wires headerNames/body options into the guard from forRoot()", async () => {
    const { BasicAuthModule, BasicAuthGuard, Test } = await importModules();
    const moduleRef = await Test.createTestingModule({
      imports: [
        BasicAuthModule.forRoot({
          credentials: { name: "u", pass: "p" },
          headerNames: { name: "x-user", pass: "x-pass" },
          body: true,
        }),
      ],
    }).compile();
    const guard = moduleRef.get(BasicAuthGuard);
    const request = { headers: { "x-user": "u", "x-pass": "p" } };
    const context = {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({}),
        getNext: () => ({}),
      }),
    } as unknown as ExecutionContext;
    expect(guard.canActivate(context)).toBe(true);
  });

  it("wires the default custom headers into the guard from forRoot() without options", async () => {
    process.env.AUTH_NAME = "envuser";
    process.env.AUTH_PASS = "envpass";
    try {
      vi.resetModules();
      const { BasicAuthModule, BasicAuthGuard, Test } = await importModules();
      const moduleRef = await Test.createTestingModule({ imports: [BasicAuthModule.forRoot()] }).compile();
      const guard = moduleRef.get(BasicAuthGuard);
      const request = { headers: { "x-auth-name": "envuser", "x-auth-pass": "envpass" } };
      const context = {
        switchToHttp: () => ({
          getRequest: () => request,
          getResponse: () => ({}),
          getNext: () => ({}),
        }),
      } as unknown as ExecutionContext;
      expect(guard.canActivate(context)).toBe(true);
    } finally {
      delete process.env.AUTH_NAME;
      delete process.env.AUTH_PASS;
    }
  });

  it("wires a multi-credential list into the guard from forRoot()", async () => {
    const { BasicAuthModule, BasicAuthGuard, Test } = await importModules();
    const moduleRef = await Test.createTestingModule({
      imports: [BasicAuthModule.forRoot({ credentials: [{ name: "u", pass: "p" }, { name: "a", pass: "b" }] })],
    }).compile();
    const guard = moduleRef.get(BasicAuthGuard);
    const ok = httpContext({ authorization: `Basic ${Buffer.from("a:b").toString("base64")}` });
    expect(guard.canActivate(ok)).toBe(true);
    const miss = httpContext({ authorization: `Basic ${Buffer.from("nope:nope").toString("base64")}` });
    expect(() => guard.canActivate(miss)).toThrow(UnauthorizedException);
  });

  it("rejects requests when forRoot() has no credentials (options and env both empty)", async () => {
    const previousName = process.env.AUTH_NAME;
    const previousPass = process.env.AUTH_PASS;
    delete process.env.AUTH_NAME;
    delete process.env.AUTH_PASS;
    try {
      vi.resetModules();
      const { BasicAuthModule, BasicAuthGuard, Test } = await importModules();
      const moduleRef = await Test.createTestingModule({ imports: [BasicAuthModule.forRoot()] }).compile();
      const guard = moduleRef.get(BasicAuthGuard);
      const ctx = httpContext({ authorization: `Basic ${Buffer.from("user:pass").toString("base64")}` });
      expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
    } finally {
      if (previousName !== undefined) process.env.AUTH_NAME = previousName;
      if (previousPass !== undefined) process.env.AUTH_PASS = previousPass;
    }
  });
});
