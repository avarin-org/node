import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import type { JsonWebSignatureHeaderParameters } from "../jsonwebsignature.header.parameters.ts";
import { JsonWebSignatureHeader } from "../jsonwebsignature.header.ts";
import { check } from "./check.ts";

class CustomJsonWebSignatureHeader extends JsonWebSignatureHeader {}

const invalidParameters: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  [],
  {},
  { alg: undefined },
  { alg: null },
  { alg: true },
  { alg: 1 },
  { alg: 1.2 },
  { alg: 1n },
  { alg: "" },
  { alg: Symbol("a") },
  { alg: Buffer },
  { alg: Buffer.alloc(0) },
  { alg: () => 1 },
  { alg: {} },
  { alg: [] },
  { alg: "A128KW" },
];

describe("check()", () => {
  const parameters: JsonWebSignatureHeaderParameters = { alg: "RS256" };

  it("should return false when the provided JSON Web Signature Header Constructor is invalid.", async () => {
    expect(check(Buffer as any, parameters)).toBe(false);
  });

  it.each(invalidParameters)(
    "should return false when the provided data is not a valid JSON Web Signature Header Parameters object with a custom JSON Web Signature Header Constructor.",
    (_parameters) => {
      expect(check(CustomJsonWebSignatureHeader, _parameters)).toBe(false);
    },
  );

  it("should return true when the provided data is a valid JSON Web Signature Header Parameters object with a custom JSON Web Signature Header Constructor.", () => {
    expect(check(CustomJsonWebSignatureHeader, parameters)).toBe(true);
  });

  it.each(invalidParameters)(
    "should return false when the provided data is not a valid JSON Web Signature Header Parameters object.",
    (_parameters) => {
      expect(check(_parameters)).toBe(false);
    },
  );

  it("should return true when the provided data is a valid JSON Web Signature Header Parameters object.", () => {
    expect(check(parameters)).toBe(true);
  });
});
