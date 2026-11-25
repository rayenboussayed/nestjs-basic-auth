import { describe, expect, it } from "vitest";
import { EnvironmentSchema } from "../../src/environment.js";

describe("EnvironmentSchema", () => {
  it("parses and trims the auth credentials and realm", () => {
    expect(EnvironmentSchema.parse({ AUTH_NAME: " admin ", AUTH_PASS: " s3cret ", AUTH_REALM: " app " })).toEqual(
      { AUTH_NAME: "admin", AUTH_PASS: "s3cret", AUTH_REALM: "app" },
    );
  });

  it("accepts an empty environment", () => {
    expect(EnvironmentSchema.parse({})).toEqual({});
  });

  it("rejects empty or whitespace-only values after trimming", () => {
    expect(() => EnvironmentSchema.parse({ AUTH_NAME: "   " })).toThrow();
    expect(() => EnvironmentSchema.parse({ AUTH_PASS: "" })).toThrow();
    expect(() => EnvironmentSchema.parse({ AUTH_REALM: "" })).toThrow();
  });

  it("rejects non-string values", () => {
    expect(() => EnvironmentSchema.parse({ AUTH_NAME: 42 })).toThrow();
  });
});
