import { performance } from "node:perf_hooks";
import { Buffer } from "node:buffer";
import { timingSafeEqual } from "node:crypto";
import { describe, expect, it } from "vitest";
import { UnauthorizedException } from "@nestjs/common";
import { parse } from "basic-auth";
import type { ExecutionContext } from "@nestjs/common";
import { BasicAuthGuard } from "../../src/basic-auth.guard.js";

const header = `Basic ${Buffer.from("user:pass").toString("base64")}`;

function averageMicros(fn: () => void, iterations: number, warmup = 1_000): number {
  for (let i = 0; i < warmup; i += 1) fn();
  const start = performance.now();
  for (let i = 0; i < iterations; i += 1) fn();
  return ((performance.now() - start) * 1_000) / iterations;
}

describe("performance", () => {
  it("parses the Authorization header fast", () => {
    const us = averageMicros(() => parse(header), 100_000);
    console.log(`parse: ${us.toFixed(3)}µs/op`);
    expect(us).toBeLessThan(50);
  });

  it("runs timing-safe compares fast", () => {
    const us = averageMicros(() => timingSafeEqual(Buffer.from("user"), Buffer.from("user")), 100_000);
    console.log(`timingSafeEqual (equal): ${us.toFixed(3)}µs/op`);
    expect(us).toBeLessThan(20);
  });

  it("runs the full guard path fast", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "user", pass: "pass" } });
    const request = { headers: { authorization: header } };
    const context = {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({ setHeader: () => {} }),
        getNext: () => ({}),
      }),
    } as unknown as ExecutionContext;
    expect(guard.canActivate(context)).toBe(true);
    const us = averageMicros(() => guard.canActivate(context), 10_000);
    console.log(`guard.canActivate: ${us.toFixed(3)}µs/op`);
    expect(us).toBeLessThan(200);
  });

  it("runs the custom-header path fast", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "user", pass: "pass" } });
    const request = { headers: { "x-auth-username": "user", "x-auth-password": "pass" } };
    const context = {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({ setHeader: () => {} }),
        getNext: () => ({}),
      }),
    } as unknown as ExecutionContext;
    expect(guard.canActivate(context)).toBe(true);
    const us = averageMicros(() => guard.canActivate(context), 10_000);
    console.log(`guard.canActivate (custom headers): ${us.toFixed(3)}µs/op`);
    expect(us).toBeLessThan(200);
  });

  it("runs the body path fast", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "user", pass: "pass" }, body: true });
    const request = { headers: {}, body: { auth: { username: "user", password: "pass" } } };
    const context = {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({ setHeader: () => {} }),
        getNext: () => ({}),
      }),
    } as unknown as ExecutionContext;
    expect(guard.canActivate(context)).toBe(true);
    const us = averageMicros(() => guard.canActivate(context), 10_000);
    console.log(`guard.canActivate (body): ${us.toFixed(3)}µs/op`);
    expect(us).toBeLessThan(200);
  });

  it("runs the multi-credential verify path fast", () => {
    const guard = new BasicAuthGuard({
      credentials: [
        { name: "user", pass: "pass" },
        { name: "admin", pass: "s3cret" },
      ],
    });
    const request = { headers: { authorization: header } };
    const context = {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({ setHeader: () => {} }),
        getNext: () => ({}),
      }),
    } as unknown as ExecutionContext;
    expect(guard.canActivate(context)).toBe(true);
    const us = averageMicros(() => guard.canActivate(context), 10_000);
    console.log(`guard.canActivate (multi-credential): ${us.toFixed(3)}µs/op`);
    expect(us).toBeLessThan(200);
  });

  it("runs the custom-header path with body enabled fast (chain stops at source 2)", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "user", pass: "pass" }, body: true });
    const request = { headers: { "x-auth-username": "user", "x-auth-password": "pass" }, body: { auth: { username: "user", password: "pass" } } };
    const context = {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({ setHeader: () => {} }),
        getNext: () => ({}),
      }),
    } as unknown as ExecutionContext;
    expect(guard.canActivate(context)).toBe(true);
    const us = averageMicros(() => guard.canActivate(context), 10_000);
    console.log(`guard.canActivate (custom headers + body enabled): ${us.toFixed(3)}µs/op`);
    expect(us).toBeLessThan(200);
  });

  it("measures the miss path when no source matches", () => {
    const guard = new BasicAuthGuard({ credentials: { name: "user", pass: "pass" }, body: true });
    const request = { headers: {}, body: undefined };
    const context = {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({ setHeader: () => {} }),
        getNext: () => ({}),
      }),
    } as unknown as ExecutionContext;
    let rejected = false;
    try {
      guard.canActivate(context);
    } catch (e) {
      rejected = e instanceof UnauthorizedException;
    }
    expect(rejected).toBe(true);
    const us = averageMicros(() => {
      try {
        guard.canActivate(context);
      } catch {
        // expected miss path
      }
    }, 10_000);
    console.log(`guard.canActivate (miss, full chain): ${us.toFixed(3)}µs/op`);
    expect(us).toBeLessThan(200);
  });
});
