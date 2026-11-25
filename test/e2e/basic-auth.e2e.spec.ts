import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Controller, Get, HttpCode, HttpStatus, Module, Post } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import type { NestApplication } from "@nestjs/core";
import { environment } from "../../src/environment.js";
import { BasicAuthGuard, BasicAuthModule } from "../../src/index.js";

@Controller("protected")
class ProtectedController {
  @Get()
  hello(): string {
    return "hello";
  }
}

@Controller("protected")
class ProtectedBodyController {
  @Post()
  @HttpCode(HttpStatus.OK)
  hello(): string {
    return "hello";
  }
}

@Module({
  imports: [BasicAuthModule.forRoot()],
  controllers: [ProtectedController],
})
class TestAppModule {}

@Module({
  imports: [BasicAuthModule.forRoot({ body: true })],
  controllers: [ProtectedBodyController],
})
class BodyAppModule {}

const encode = (text: string): string => Buffer.from(text, "utf8").toString("base64");

describe("BasicAuthModule (e2e)", () => {
  let baseUrl: string;
  let app: NestApplication;

  beforeAll(async () => {
    app = await NestFactory.create(TestAppModule);
    app.useGlobalGuards(new BasicAuthGuard({ credentials: { name: "user", pass: "pass" } }));
    await app.listen(0, "127.0.0.1");
    const address = app.getHttpServer().address();
    if (typeof address !== "object" || address === null) {
      throw new Error("server is not listening");
    }
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    await app.close();
  });

  it("rejects missing credentials with 401 + WWW-Authenticate", async () => {
    const res = await fetch(`${baseUrl}/protected`);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toMatch(/Basic/i);
  });

  it("returns an exact WWW-Authenticate challenge format on 401", async () => {
    const res = await fetch(`${baseUrl}/protected`);
    const challenge = res.headers.get("www-authenticate");
    expect(challenge).toMatch(/^Basic realm="[^"]+"$/);
    // No realm is configured here, so the challenge uses the default realm.
    if (environment.AUTH_REALM === undefined) {
      expect(challenge).toBe('Basic realm="Secure Area"');
    }
  });

  it("accepts correct credentials", async () => {
    const res = await fetch(`${baseUrl}/protected`, {
      headers: { authorization: `Basic ${encode("user:pass")}` },
    });
    expect(res.status).toBe(200);
  });

  it("accepts credentials from the custom x-auth-username/x-auth-password headers", async () => {
    const res = await fetch(`${baseUrl}/protected`, {
      headers: { "x-auth-username": "user", "x-auth-password": "pass" },
    });
    expect(res.status).toBe(200);
  });

  it("prefers the Authorization header over the custom headers", async () => {
    const res = await fetch(`${baseUrl}/protected`, {
      headers: { authorization: `Basic ${encode("user:pass")}`, "x-auth-username": "wrong", "x-auth-password": "wrong" },
    });
    expect(res.status).toBe(200);
  });

  it("rejects when the custom headers are present but do not match", async () => {
    const res = await fetch(`${baseUrl}/protected`, {
      headers: { "x-auth-username": "user", "x-auth-password": "wrong" },
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toMatch(/Basic/i);
  });

  it("rejects when only one custom header is present", async () => {
    const res = await fetch(`${baseUrl}/protected`, {
      headers: { "x-auth-username": "user" },
    });
    expect(res.status).toBe(401);
  });

  it("rejects wrong credentials", async () => {
    const res = await fetch(`${baseUrl}/protected`, {
      headers: { authorization: `Basic ${encode("user:wrong")}` },
    });
    expect(res.status).toBe(401);
  });

  it("accepts any credential from the multi-credential list", async () => {
    const guard = new BasicAuthGuard({
      credentials: [
        { name: "user", pass: "pass" },
        { name: "admin", pass: "s3cret" },
      ],
    });
    const base = await NestFactory.create(TestAppModule);
    try {
      base.useGlobalGuards(guard);
      await base.listen(0, "127.0.0.1");
      const address = base.getHttpServer().address();
      if (typeof address !== "object" || address === null) throw new Error("not listening");
      const res = await fetch(`http://127.0.0.1:${address.port}/protected`, {
        headers: { authorization: `Basic ${encode("admin:s3cret")}` },
      });
      expect(res.status).toBe(200);
    } finally {
      await base.close();
    }
  });
});

describe("BasicAuthModule (e2e, body credentials)", () => {
  let baseUrl: string;
  let app: NestApplication;

  beforeAll(async () => {
    app = await NestFactory.create(BodyAppModule);
    app.useGlobalGuards(new BasicAuthGuard({ credentials: { name: "user", pass: "pass" }, body: true }));
    await app.listen(0, "127.0.0.1");
    const address = app.getHttpServer().address();
    if (typeof address !== "object" || address === null) {
      throw new Error("server is not listening");
    }
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    await app.close();
  });

  it("accepts credentials from body.auth.username/password on a POST request", async () => {
    const res = await fetch(`${baseUrl}/protected`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ auth: { username: "user", password: "pass" } }),
    });
    expect(res.status).toBe(200);
  });

  it("rejects missing body credentials with 401 + WWW-Authenticate", async () => {
    const res = await fetch(`${baseUrl}/protected`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ auth: {} }),
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toMatch(/Basic/i);
  });
});
