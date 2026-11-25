import "reflect-metadata";
import { describe, expect, it } from "vitest";
import type { ExecutionContext } from "@nestjs/common";
import { BasicAuthGuard } from "../../src/basic-auth.guard.js";
import { SkipBasicAuth } from "../../src/skip-basic-auth.decorator.js";

class PublicController {
  @SkipBasicAuth()
  publicRoute() {}
}

const ITERATIONS = 10_000;

function createContext(body?: unknown) {
  const request = { headers: { authorization: `Basic ${Buffer.from("user:pass").toString("base64")}` }, body };
  return {
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => ({ setHeader: () => {} }),
      getNext: () => ({}),
    }),
  } as unknown as ExecutionContext;
}

function createCustomHeaderContext() {
  const request = { headers: { "x-auth-name": "user", "x-auth-pass": "pass" } };
  return {
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => ({ setHeader: () => {} }),
      getNext: () => ({}),
    }),
  } as unknown as ExecutionContext;
}

const gc = (globalThis as { gc?: () => void }).gc;

// Without --expose-gc (e.g. the coverage run) there is no forced GC, so the
// measured heap delta also includes uncollected garbage — use a looser bound.
const maxGrowthMB = gc === undefined ? 25 : 5;

async function growthMB(guard: BasicAuthGuard, create: () => ExecutionContext) {
  const run = async () => {
    for (let i = 0; i < ITERATIONS; i += 1) {
      await guard.canActivate(create());
    }
  };
  await run(); // warm-up
  gc?.();
  const before = process.memoryUsage().heapUsed;
  await run();
  gc?.();
  gc?.();
  return (process.memoryUsage().heapUsed - before) / (1024 * 1024);
}

describe("memory", () => {
  it("does not grow the heap across repeated guard calls", async () => {
    const guard = new BasicAuthGuard({ credentials: { name: "user", pass: "pass" } });
    const first = await growthMB(guard, createContext);
    const second = await growthMB(guard, createContext);
    console.log(`heap growth after 10,000 calls: first=${first.toFixed(2)}MB second=${second.toFixed(2)}MB`);
    expect(second).toBeLessThan(maxGrowthMB);
  });

  it("does not grow the heap across repeated guard calls using body credentials", async () => {
    const guard = new BasicAuthGuard({ credentials: { name: "user", pass: "pass" }, body: true });
    const first = await growthMB(guard, () => createContext({ auth: { name: "user", pass: "pass" } }));
    const second = await growthMB(guard, () => createContext({ auth: { name: "user", pass: "pass" } }));
    console.log(`heap growth (body path) after 10,000 calls: first=${first.toFixed(2)}MB second=${second.toFixed(2)}MB`);
    expect(second).toBeLessThan(maxGrowthMB);
  });

  it("does not grow the heap across repeated guard calls using custom headers", async () => {
    const guard = new BasicAuthGuard({ credentials: { name: "user", pass: "pass" } });
    const first = await growthMB(guard, createCustomHeaderContext);
    const second = await growthMB(guard, createCustomHeaderContext);
    console.log(`heap growth (custom headers) after 10,000 calls: first=${first.toFixed(2)}MB second=${second.toFixed(2)}MB`);
    expect(second).toBeLessThan(maxGrowthMB);
  });

  it("does not grow the heap across repeated guard calls on the public skip path", async () => {
    const guard = new BasicAuthGuard({ credentials: { name: "user", pass: "pass" } });
    const skippedContext = () =>
      ({
        switchToHttp: () => ({
          getRequest: () => ({ headers: {} }),
          getResponse: () => ({}),
          getNext: () => ({}),
        }),
        getHandler: () => PublicController.prototype.publicRoute,
        getClass: () => PublicController,
      }) as unknown as ExecutionContext;
    const first = await growthMB(guard, skippedContext);
    const second = await growthMB(guard, skippedContext);
    console.log(`heap growth (skip path) after 10,000 calls: first=${first.toFixed(2)}MB second=${second.toFixed(2)}MB`);
    expect(second).toBeLessThan(maxGrowthMB);
  });

  it("does not grow the heap across repeated guard calls on the multi-credential path", async () => {
    const guard = new BasicAuthGuard({
      credentials: [
        { name: "user", pass: "pass" },
        { name: "admin", pass: "s3cret" },
        { name: "bot", pass: "vibes" },
      ],
    });
    const first = await growthMB(guard, createContext);
    const second = await growthMB(guard, createContext);
    console.log(`heap growth (multi-credential) after 10,000 calls: first=${first.toFixed(2)}MB second=${second.toFixed(2)}MB`);
    expect(second).toBeLessThan(maxGrowthMB);
  });
});
