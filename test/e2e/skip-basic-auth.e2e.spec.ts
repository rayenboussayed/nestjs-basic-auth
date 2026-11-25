import "reflect-metadata";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Controller, Get, Module, Req } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import type { NestApplication } from "@nestjs/core";
import { BasicAuthGuard, BasicAuthModule, SkipBasicAuth } from "../../src/index.js";

interface RequestWithUser {
  user?: unknown;
}

function whoami(request: RequestWithUser) {
  return { user: request.user ?? null };
}

@Controller("public")
@SkipBasicAuth()
class PublicController {
  @Get("whoami")
  whoami(@Req() request: RequestWithUser) {
    return whoami(request);
  }
}

@Controller("mixed")
class MixedController {
  @Get("whoami")
  @SkipBasicAuth()
  whoami(@Req() request: RequestWithUser) {
    return whoami(request);
  }

  @Get("locked")
  locked() {
    return "locked";
  }
}

@Module({
  imports: [BasicAuthModule.forRoot()],
  controllers: [PublicController, MixedController],
})
class TestAppModule {}

const encode = (text: string) => Buffer.from(text, "utf8").toString("base64");
const validAuth = { authorization: `Basic ${encode("user:pass")}` };

describe("@SkipBasicAuth() (e2e)", () => {
  let baseUrl: string;
  let app: NestApplication;

  beforeAll(async () => {
    app = await NestFactory.create(TestAppModule);
    app.useGlobalGuards(new BasicAuthGuard({ credentials: { name: "user", pass: "pass" } }));
    await app.listen(0, "127.0.0.1");
    const address = app.getHttpServer().address();
    if (typeof address !== "object" || address === null) throw new Error("server is not listening");
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    await app.close();
  });

  it("allows a controller-level public route with no credentials and leaves req.user unset", async () => {
    const res = await fetch(`${baseUrl}/public/whoami`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user: null });
    expect(res.headers.get("www-authenticate")).toBeNull();
  });

  it("allows a handler-level public route with no credentials and leaves req.user unset", async () => {
    const res = await fetch(`${baseUrl}/mixed/whoami`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user: null });
    expect(res.headers.get("www-authenticate")).toBeNull();
  });

  it("skips auth on a public route even when credentials are supplied", async () => {
    const res = await fetch(`${baseUrl}/mixed/whoami`, { headers: validAuth });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user: null });
  });

  it("skips auth on a public route even when the Authorization header is malformed", async () => {
    const res = await fetch(`${baseUrl}/mixed/whoami`, { headers: { authorization: "Bearer token" } });
    expect(res.status).toBe(200);
    expect(res.headers.get("www-authenticate")).toBeNull();
  });

  it("still protects an unmarked route in the same application", async () => {
    const missing = await fetch(`${baseUrl}/mixed/locked`);
    expect(missing.status).toBe(401);
    expect(missing.headers.get("www-authenticate")).toMatch(/Basic/i);

    const ok = await fetch(`${baseUrl}/mixed/locked`, { headers: validAuth });
    expect(ok.status).toBe(200);
    expect(await ok.text()).toBe("locked");
  });
});
