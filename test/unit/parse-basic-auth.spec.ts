import { describe, expect, it } from "vitest";
import { parse } from "basic-auth";

const b64 = (value: string) => Buffer.from(value, "utf8").toString("base64");

describe("parse (npm package)", () => {
  it("parses valid credentials and returns { name, pass }", () => {
    expect(parse(`Basic ${b64("user:pass")}`)).toEqual({ name: "user", pass: "pass" });
  });

  it("returns undefined for missing, empty and non-Basic headers", () => {
    expect(parse("")).toBeUndefined();
    expect(parse("Basic")).toBeUndefined();
    expect(parse("Basic   ")).toBeUndefined();
    expect(parse("Bearer dXNlcjpwYXNz")).toBeUndefined();
  });

  it("returns undefined when the decoded string has no colon", () => {
    expect(parse(`Basic ${b64("nocolon")}`)).toBeUndefined();
  });

  it("throws TypeError when passed a non-string", () => {
    expect(() => parse(undefined as unknown as string)).toThrow(TypeError);
  });
});
