import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import type { JsonWebEncryptionHeaderParameters } from "../jsonwebencryption.header.parameters.ts";
import { JsonWebEncryptionHeader } from "../jsonwebencryption.header.ts";
import { check } from "./check.ts";

class CustomJsonWebEncryptionHeader extends JsonWebEncryptionHeader {}

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
  { alg: "RS256" },
  { alg: "A128GCMKW", enc: undefined },
  { alg: "A128GCMKW", enc: null },
  { alg: "A128GCMKW", enc: true },
  { alg: "A128GCMKW", enc: 1 },
  { alg: "A128GCMKW", enc: 1.2 },
  { alg: "A128GCMKW", enc: 1n },
  { alg: "A128GCMKW", enc: "" },
  { alg: "A128GCMKW", enc: Symbol("a") },
  { alg: "A128GCMKW", enc: Buffer },
  { alg: "A128GCMKW", enc: Buffer.alloc(0) },
  { alg: "A128GCMKW", enc: () => 1 },
  { alg: "A128GCMKW", enc: {} },
  { alg: "A128GCMKW", enc: [] },
  { alg: "A128GCMKW", enc: "A128CBC-HS256", zip: undefined },
  { alg: "A128GCMKW", enc: "A128CBC-HS256", zip: null },
  { alg: "A128GCMKW", enc: "A128CBC-HS256", zip: true },
  { alg: "A128GCMKW", enc: "A128CBC-HS256", zip: 1 },
  { alg: "A128GCMKW", enc: "A128CBC-HS256", zip: 1.2 },
  { alg: "A128GCMKW", enc: "A128CBC-HS256", zip: 1n },
  { alg: "A128GCMKW", enc: "A128CBC-HS256", zip: "" },
  { alg: "A128GCMKW", enc: "A128CBC-HS256", zip: Symbol("a") },
  { alg: "A128GCMKW", enc: "A128CBC-HS256", zip: Buffer },
  { alg: "A128GCMKW", enc: "A128CBC-HS256", zip: Buffer.alloc(0) },
  { alg: "A128GCMKW", enc: "A128CBC-HS256", zip: () => 1 },
  { alg: "A128GCMKW", enc: "A128CBC-HS256", zip: {} },
  { alg: "A128GCMKW", enc: "A128CBC-HS256", zip: [] },
];

describe("check()", () => {
  const parameters: JsonWebEncryptionHeaderParameters = { alg: "A128GCMKW", enc: "A128CBC-HS256" };

  it("should return false when the provided JSON Web Encryption Header Constructor is invalid.", async () => {
    expect(check(Buffer as any, parameters)).toBe(false);
  });

  it.each(invalidParameters)(
    "should return false when the provided data is not a valid JSON Web Encryption Header Parameters object with a custom JSON Web Encryption Header Constructor.",
    (_parameters) => {
      expect(check(CustomJsonWebEncryptionHeader, _parameters)).toBe(false);
    },
  );

  it("should return true when the provided data is a valid JSON Web Encryption Header Parameters object with a custom JSON Web Encryption Header Constructor.", () => {
    expect(check(CustomJsonWebEncryptionHeader, parameters)).toBe(true);
  });

  it.each(invalidParameters)(
    "should return false when the provided data is not a valid JSON Web Encryption Header Parameters object.",
    (_parameters) => {
      expect(check(_parameters)).toBe(false);
    },
  );

  it("should return true when the provided data is a valid JSON Web Encryption Header Parameters object.", () => {
    expect(check(parameters)).toBe(true);
  });
});
