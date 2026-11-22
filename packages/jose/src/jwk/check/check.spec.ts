import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import type { JsonWebKeyParameters } from "../jsonwebkey.parameters.ts";
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
  { use: 123 },
];

describe("check()", () => {
  it.each(invalidParameters)(
    "should return false when the provided data is not a valid JSON Web Key Parameters object.",
    (parameters) => {
      expect(check(parameters)).toBe(false);
    },
  );

  it("should return true when the provided data is a valid JSON Web Key Parameters object.", () => {
    const parameters: JsonWebKeyParameters = {
      alg: "ES256",
      crv: "P-256",
      kid: "BIeu8EdR3YOIwXbP",
      kty: "EC",
      x: "4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og",
      y: "mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8",
    };

    expect(check(parameters)).toBe(true);
  });
});
