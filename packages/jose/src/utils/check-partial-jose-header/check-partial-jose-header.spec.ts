import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import type { JoseHeaderParameters } from "../../jose/header/jose.header.parameters.ts";
import { checkPartialJoseHeader } from "./check-partial-jose-header.ts";

const invalidParameters: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
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
];

describe("checkPartialJoseHeader()", () => {
  it.each(invalidParameters)(
    "should return false when the provided data is not a valid JOSE Header Parameters object.",
    (parameters) => {
      expect(checkPartialJoseHeader(parameters)).toBe(false);
    },
  );

  it("should return true when the provided data is a valid JOSE Header Parameters object.", () => {
    const parameters: Partial<JoseHeaderParameters> = { kid: "key-id" };
    expect(checkPartialJoseHeader(parameters)).toBe(true);
  });
});
