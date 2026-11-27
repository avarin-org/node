import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import type { CompactJsonWebEncryptionParameters } from "../compact.jsonwebencryption.parameters.ts";
import { decode } from "./decode.ts";

const invalidTokens: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  "",
];

const invalidTokenFormats = ["a", ".a", ".a.b.c.d", "a.b", "a.b.c.d.e.f"];

describe("decode()", () => {
  const headerlessToken =
    "." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
    "U0m_YmjN04DJvceFICbCVQ";

  const invalidHeaderToken =
    "ew." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
    "U0m_YmjN04DJvceFICbCVQ";

  const attachedToken =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
    "U0m_YmjN04DJvceFICbCVQ";

  const detachedToken =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "." +
    "U0m_YmjN04DJvceFICbCVQ";

  const protectedHeader: JsonWebEncryptionHeaderParameters = { alg: "A128KW", enc: "A128CBC-HS256" };

  const encryptedKey = Buffer.from("6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ", "base64url");
  const initializationVector = Buffer.from("AxY8DCtDaGlsbGljb3RoZQ", "base64url");
  const ciphertext = Buffer.from("KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY", "base64url");
  const authenticationTag = Buffer.from("U0m_YmjN04DJvceFICbCVQ", "base64url");
  const additionalAuthenticatedData = Buffer.from("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", "ascii");

  it.each(invalidTokens)("should throw when the provided Compact JSON Web Encryption Token is invalid.", (token) => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    expect(() => decode(token)).toThrow(error);
  });

  it.each(invalidTokenFormats)(
    "should throw when the provided Compact JSON Web Encryption Token has an invalid format.",
    (token) => {
      const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
      expect(() => decode(token)).toThrow(error);
    },
  );

  it("should throw when failing to parse the Protected Header of the provided Compact JSON Web Encryption Token.", () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    expect(() => decode(headerlessToken)).toThrow(error);
  });

  it("should throw when the Protected Header of the provided Compact JSON Web Encryption Token is invalid.", () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    expect(() => decode(invalidHeaderToken)).toThrow(error);
  });

  it("should return the Compact JSON Web Encryption Parameters from an Attached Compact JSON Web Encryption Token.", () => {
    expect(decode(attachedToken)).toStrictEqual<CompactJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag,
      ciphertext,
      encryptedKey,
      initializationVector,
      joseHeader: protectedHeader,
    });
  });

  it("should return the Compact JSON Web Encryption Parameters from a Detached Compact JSON Web Encryption Token.", () => {
    expect(decode(detachedToken)).toStrictEqual<CompactJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag,
      ciphertext: null,
      encryptedKey,
      initializationVector,
      joseHeader: protectedHeader,
    });
  });
});
