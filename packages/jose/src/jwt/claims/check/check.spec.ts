import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import type { JsonWebTokenClaimsParameters } from "../jsonwebtoken.claims.parameters.ts";
import { JsonWebTokenClaims } from "../jsonwebtoken.claims.ts";
import { check } from "./check.ts";

class CustomJsonWebTokenClaims extends JsonWebTokenClaims {}

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
  { sub: undefined },
  { sub: null },
  { sub: true },
  { sub: 1 },
  { sub: 1.2 },
  { sub: 1n },
  { sub: "" },
  { sub: Symbol("a") },
  { sub: Buffer },
  { sub: Buffer.alloc(0) },
  { sub: () => 1 },
  { sub: {} },
  { sub: [] },
];

describe("check()", () => {
  const parameters: JsonWebTokenClaimsParameters = { sub: "7TmNm32xoltK8n4O" };

  it("should return false when the provided JSON Web Token Claims Constructor is invalid.", async () => {
    expect(check(Buffer as any, parameters)).toBe(false);
  });

  it.each(invalidParameters)(
    "should return false when the provided data is not a valid JSON Web Signature Header Parameters object with a custom JSON Web Token Claims Constructor.",
    (_parameters) => {
      expect(check(CustomJsonWebTokenClaims, _parameters)).toBe(false);
    },
  );

  it("should return true when the provided data is a valid JSON Web Signature Header Parameters object with a custom JSON Web Token Claims Constructor.", () => {
    expect(check(CustomJsonWebTokenClaims, parameters)).toBe(true);
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
