import { describe, expect, it } from "vitest";
import { UnauthorizedException } from "@nestjs/common";
import type { ExecutionContext } from "@nestjs/common";
import { environment } from "../../src/environment.js";
import { BasicAuthGuard } from "../../src/basic-auth.guard.js";

interface TestRequest {
  headers: Record<string, string | string[]>;
  body?: unknown;
  user?: { name: string; pass: string };
}

interface TestContext {
  context: ExecutionContext;
  request: TestRequest;
  wwwAuthenticate: string[];
}

function createContext(headers: Record<string, string | string[]>, body?: unknown): TestContext {
  const request: TestRequest = { headers, body };
  const wwwAuthenticate: string[] = [];
  const response = {
    setHeader: (name: string, value: string): void => {
      if (name.toLowerCase() === "www-authenticate") {
        wwwAuthenticate.push(value);
      }
    },
  };
  const context = {
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => response,
      getNext: () => ({}),
    }),
  } as unknown as ExecutionContext;
  return { context, request, wwwAuthenticate };
}

const encode = (text: string): string => Buffer.from(text, "utf8").toString("base64");

describe("BasicAuthGuard", () => {
  it("accepts valid credentials and exposes them via req.user", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "admin", pass: "s3cret" } });
    const { context, request } = createContext({ authorization: `Basic ${encode("admin:s3cret")}` });
    expect(guard.canActivate(context)).toBe(true);
    expect(request.user).toEqual({ name: "admin", pass: "s3cret" });
  });

  it("throws 401 and sets WWW-Authenticate when the header is missing", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "admin", pass: "s3cret" } });
    const { context, wwwAuthenticate } = createContext({});
    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
    expect(wwwAuthenticate).toHaveLength(1);
  });

  it("throws 401 and sets WWW-Authenticate for malformed or wrong headers", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "admin", pass: "s3cret" } });
    const headers = [
      "Basic",
      "Basic ",
      "Basic   ",
      "basic !!!",
      "Bearer dXNlcjpwYXNz",
      `Basic ${encode("nocolon")}`,
      `Basic ${encode("admin:wrong")}`,
    ];
    for (const header of headers) {
      const { context } = createContext({ authorization: header });
      expect(() => guard.canActivate(context), `header: ${header}`).toThrow(UnauthorizedException);
    }
  });

  it("reads credentials from a custom header name", () => {
    const guard = new BasicAuthGuard({ header: "x-basic-auth", credentials: { name: "u", pass: "p" } });
    const ok = createContext({ "x-basic-auth": `Basic ${encode("u:p")}` });
    expect(guard.canActivate(ok.context)).toBe(true);
    const missing = createContext({ authorization: `Basic ${encode("u:p")}` });
    expect(() => guard.canActivate(missing.context)).toThrow(UnauthorizedException);
  });

  it("falls back to the AUTH_USERNAME/AUTH_PASSWORD environment credentials", () => {
    const previousUsername = environment.AUTH_USERNAME;
    const previousPassword = environment.AUTH_PASSWORD;
    environment.AUTH_USERNAME = "envuser";
    environment.AUTH_PASSWORD = "envpass";
    try {
      const guard = new BasicAuthGuard();
      const { context } = createContext({ authorization: `Basic ${encode("envuser:envpass")}` });
      expect(guard.canActivate(context)).toBe(true);
    } finally {
      if (previousUsername === undefined) {
        delete environment.AUTH_USERNAME;
      } else {
        environment.AUTH_USERNAME = previousUsername;
      }
      if (previousPassword === undefined) {
        delete environment.AUTH_PASSWORD;
      } else {
        environment.AUTH_PASSWORD = previousPassword;
      }
    }
  });

  it("accepts any of multiple configured credentials", () => {
    const guard = new BasicAuthGuard({
      credentials: [
        { name: "a", pass: "1" },
        { name: "b", pass: "2" },
        { name: "c", pass: "3" },
      ],
    });
    const ok = createContext({ authorization: `Basic ${encode("b:2")}` });
    expect(guard.canActivate(ok.context)).toBe(true);
    const noMatch = createContext({ authorization: `Basic ${encode("a:nope")}` });
    expect(() => guard.canActivate(noMatch.context)).toThrow(UnauthorizedException);
  });

  it("accepts empty username and password when configured", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "", pass: "" } });
    const { context } = createContext({ authorization: `Basic ${encode(":")}` });
    expect(guard.canActivate(context)).toBe(true);
  });

  it("uses the realm from options, AUTH_REALM, then defaults to Secure Area", () => {
    const previousRealm = environment.AUTH_REALM;
    environment.AUTH_REALM = undefined;
    try {
      const guard = new BasicAuthGuard({ realm: "app", credentials: { name: "u", pass: "p" } });
      const { context, wwwAuthenticate } = createContext({});
      expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
      expect(wwwAuthenticate[0]).toContain('Basic realm="app"');

      const envGuard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" } });
      environment.AUTH_REALM = "from-env";
      const { context: envContext, wwwAuthenticate: envChallenges } = createContext({});
      expect(() => envGuard.canActivate(envContext)).toThrow(UnauthorizedException);
      expect(envChallenges[0]).toContain('Basic realm="from-env"');

      const defaultGuard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" } });
      environment.AUTH_REALM = undefined;
      const { context: defaultContext, wwwAuthenticate: defaultChallenges } = createContext({});
      expect(() => defaultGuard.canActivate(defaultContext)).toThrow(UnauthorizedException);
      expect(defaultChallenges[0]).toContain('Basic realm="Secure Area"');
    } finally {
      if (previousRealm === undefined) {
        delete environment.AUTH_REALM;
      } else {
        environment.AUTH_REALM = previousRealm;
      }
    }
  });

  it("falls back to the default x-auth-username/x-auth-password headers", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" } });
    const { context, request } = createContext({ "x-auth-username": "u", "x-auth-password": "p" });
    expect(guard.canActivate(context)).toBe(true);
    expect(request.user).toEqual({ name: "u", pass: "p" });
  });

  it("prefers the standard Authorization header over custom headers", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" } });
    const { context, request } = createContext({
      authorization: `Basic ${encode("u:p")}`,
      "x-auth-username": "wrong",
      "x-auth-password": "wrong",
    });
    expect(guard.canActivate(context)).toBe(true);
    expect(request.user).toEqual({ name: "u", pass: "p" });
  });

  it("prefers custom headers over the body", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" }, body: true });
    const { context, request } = createContext({ "x-auth-username": "u", "x-auth-password": "p" }, { auth: { username: "wrong", password: "wrong" } });
    expect(guard.canActivate(context)).toBe(true);
    expect(request.user).toEqual({ name: "u", pass: "p" });
  });

  it("reads credentials from body.auth.username/password when body: true", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" }, body: true });
    const { context, request } = createContext({}, { auth: { username: "u", password: "p" } });
    expect(guard.canActivate(context)).toBe(true);
    expect(request.user).toEqual({ name: "u", pass: "p" });
  });

  it("rejects body credentials when the body option is not set", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" } });
    const { context } = createContext({}, { auth: { username: "u", password: "p" } });
    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
  });

  it("falls through to the body when custom headers are incomplete", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" }, body: true });
    const { context, request } = createContext({ "x-auth-username": "u" }, { auth: { username: "u", password: "p" } });
    expect(guard.canActivate(context)).toBe(true);
    expect(request.user).toEqual({ name: "u", pass: "p" });
  });

  it("ignores body credentials with non-string values", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" }, body: true });
    const { context } = createContext({}, { auth: { username: 42, password: "p" } });
    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
  });

  it("reads credentials from custom headerNames when configured", () => {
    const guard = new BasicAuthGuard({
      credentials: { name: "u", pass: "p" },
      headerNames: { username: "x-user", password: "x-pass" },
    });
    const { context, request } = createContext({ "x-user": "u", "x-pass": "p" });
    expect(guard.canActivate(context)).toBe(true);
    expect(request.user).toEqual({ name: "u", pass: "p" });
    const missing = createContext({ "x-user": "u" });
    expect(() => guard.canActivate(missing.context)).toThrow(UnauthorizedException);
  });

  it("treats empty custom header values as absent (no credentials from the custom headers)", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" } });
    const { context } = createContext({ "x-auth-username": "u", "x-auth-password": "" });
    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
  });

  it("rejects custom headers that are present but wrong, even with valid body credentials", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" }, body: true });
    const { context } = createContext(
      { "x-auth-username": "wrong", "x-auth-password": "wrong" },
      { auth: { username: "u", password: "p" } },
    );
    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
  });

  it("rejects (without fallback) when the standard header is present but malformed, even with custom headers present", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" } });
    const { context } = createContext({
      authorization: "Bearer token",
      "x-auth-username": "u",
      "x-auth-password": "p",
    });
    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
  });

  it("escapes quotes and backslashes in the realm when building the challenge", () => {
    const guard = new BasicAuthGuard({ realm: 'a"b\\c', credentials: { name: "u", pass: "p" } });
    const { context, wwwAuthenticate } = createContext({});
    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
    expect(wwwAuthenticate[0]).toBe('Basic realm="a\\"b\\\\c"');
  });

  it("reads the first element of array-valued standard headers", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "user", pass: "pass" } });
    const { context, request } = createContext({ authorization: [`Basic ${encode("user:pass")}`] });
    expect(guard.canActivate(context)).toBe(true);
    expect(request.user).toEqual({ name: "user", pass: "pass" });
  });

  it("matches the standard header name case-insensitively", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" }, header: "X-Basic-Auth" });
    const { context, request } = createContext({ "x-basic-auth": `Basic ${encode("u:p")}` });
    expect(guard.canActivate(context)).toBe(true);
    expect(request.user).toEqual({ name: "u", pass: "p" });
  });

  it("rejects when only one of AUTH_USERNAME/AUTH_PASSWORD is set", () => {
    const previousUsername = environment.AUTH_USERNAME;
    const previousPassword = environment.AUTH_PASSWORD;
    environment.AUTH_USERNAME = "envuser";
    delete environment.AUTH_PASSWORD;
    try {
      const guard = new BasicAuthGuard();
      const { context } = createContext({ authorization: `Basic ${encode("envuser:pass")}` });
      expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
    } finally {
      if (previousUsername !== undefined) environment.AUTH_USERNAME = previousUsername;
      if (previousPassword !== undefined) environment.AUTH_PASSWORD = previousPassword;
    }
  });

  it("rejects a valid header when no credentials are configured at all", () => {
    const previousUsername = environment.AUTH_USERNAME;
    const previousPassword = environment.AUTH_PASSWORD;
    delete environment.AUTH_USERNAME;
    delete environment.AUTH_PASSWORD;
    try {
      const guard = new BasicAuthGuard();
      const { context } = createContext({ authorization: `Basic ${encode("user:pass")}` });
      expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
    } finally {
      if (previousUsername !== undefined) environment.AUTH_USERNAME = previousUsername;
      if (previousPassword !== undefined) environment.AUTH_PASSWORD = previousPassword;
    }
  });

  it("still throws 401 without setting a challenge when the response has neither setHeader nor header", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" } });
    const context = {
      switchToHttp: () => ({
        getRequest: () => ({ headers: {} }),
        getResponse: () => ({}),
        getNext: () => ({}),
      }),
    } as unknown as ExecutionContext;
    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
  });

  it("treats a null body.auth as absent (401)", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" }, body: true });
    const { context } = createContext({}, { auth: null });
    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
  });

  it("treats non-object bodies as absent when body: true", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "u", pass: "p" }, body: true });
    const { context } = createContext({}, "not-an-object");
    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
  });

  it("rejects when provided credentials have different lengths than the expected pair", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "user", pass: "pass" } });
    const longerName = createContext({ authorization: `Basic ${encode("username:pass")}` });
    expect(() => guard.canActivate(longerName.context)).toThrow(UnauthorizedException);
    const longerPass = createContext({ authorization: `Basic ${encode("user:passss")}` });
    expect(() => guard.canActivate(longerPass.context)).toThrow(UnauthorizedException);
  });
});
