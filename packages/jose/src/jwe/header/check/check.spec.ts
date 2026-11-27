import { Buffer } from "node:buffer";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { jose } from "../../../jose/index.ts";
import type { JsonWebEncryptionHeaderParameters } from "../jsonwebencryption.header.parameters.ts";
import { JsonWebEncryptionHeader } from "../jsonwebencryption.header.ts";
import { check } from "./check.ts";

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

  let joseHeaderCheckSpy: Mock;

  beforeEach(() => {
    joseHeaderCheckSpy = vi.spyOn(jose.header, "check");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each(invalidParameters)(
    "should return false when the provided data is not a valid JSON Web Encryption Header Parameters object.",
    (_parameters) => {
      expect(check(_parameters)).toBe(false);
      expect(joseHeaderCheckSpy).toHaveBeenCalledExactlyOnceWith(JsonWebEncryptionHeader, _parameters);
    },
  );

  it("should return true when the provided data is a valid JSON Web Encryption Header Parameters object.", () => {
    expect(check(parameters)).toBe(true);
    expect(joseHeaderCheckSpy).toHaveBeenCalledExactlyOnceWith(JsonWebEncryptionHeader, parameters);
  });
});
