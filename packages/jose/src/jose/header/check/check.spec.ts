import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import type { JoseHeaderParameters } from "../jose.header.parameters.ts";
import { JoseHeader } from "../jose.header.ts";
import { check } from "./check.ts";

class CustomJoseHeader extends JoseHeader {}

const invalidHeaderConstructors: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  Buffer,
];

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
  { kid: undefined },
  { kid: null },
  { kid: true },
  { kid: 1 },
  { kid: 1.2 },
  { kid: 1n },
  { kid: Symbol("a") },
  { kid: Buffer },
  { kid: Buffer.alloc(0) },
  { kid: () => 1 },
  { kid: {} },
  { kid: [] },
  { kid: "" },
];

describe("check()", () => {
  const parameters: Partial<JoseHeaderParameters> = { kid: "jMrjx6cpYbG2e8g5" };

  it.each(invalidHeaderConstructors)(
    "should return false when the provided JOSE Header Constructor is invalid.",
    async (HeaderConstructor) => {
      expect(check(HeaderConstructor, parameters)).toBe(false);
    },
  );

  it.each(invalidParameters)(
    "should return false when the provided data is not a valid JOSE Header Parameters object.",
    (_parameters) => {
      expect(check(CustomJoseHeader, _parameters)).toBe(false);
    },
  );

  it("should return true when the provided data is a valid JOSE Header Parameters object.", () => {
    expect(check(CustomJoseHeader, parameters)).toBe(true);
  });
});
