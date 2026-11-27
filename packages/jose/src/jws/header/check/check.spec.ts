import { Buffer } from "node:buffer";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { jose } from "../../../jose/index.ts";
import type { JsonWebSignatureHeaderParameters } from "../jsonwebsignature.header.parameters.ts";
import { JsonWebSignatureHeader } from "../jsonwebsignature.header.ts";
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
  { alg: "A128KW" },
];

describe("check()", () => {
  const parameters: JsonWebSignatureHeaderParameters = { alg: "RS256" };

  let joseHeaderCheckSpy: Mock;

  beforeEach(() => {
    joseHeaderCheckSpy = vi.spyOn(jose.header, "check");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each(invalidParameters)(
    "should return false when the provided data is not a valid JSON Web Signature Header Parameters object.",
    (_parameters) => {
      expect(check(_parameters)).toBe(false);
      expect(joseHeaderCheckSpy).toHaveBeenCalledExactlyOnceWith(JsonWebSignatureHeader, _parameters);
    },
  );

  it("should return true when the provided data is a valid JSON Web Signature Header Parameters object.", () => {
    expect(check(parameters)).toBe(true);
    expect(joseHeaderCheckSpy).toHaveBeenCalledExactlyOnceWith(JsonWebSignatureHeader, parameters);
  });
});
