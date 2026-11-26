import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import { JsonWebEncryptionHeader } from "../../../header/jsonwebencryption.header.ts";
import type { CompactJsonWebEncryption } from "../compact.jsonwebencryption.ts";
import { deserialize } from "./deserialize.ts";

const invalidDeserializeOptions: any[] = [
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
];

const invalidJsonWebKeys: any[] = [
  undefined,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
];

const invalidExpectedAlgorithms: any[] = [
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
  {},
  [],
  ["a"],
];

const invalidDetachedCiphertexts: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol("a"),
  Buffer,
  () => 1,
  {},
  [],
  Buffer.alloc(0),
];

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

describe("deserialize()", () => {
  const wrongEncryptedKeyToken =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
    "anBl9PSuJobKWwzWzJCqfMnejCvM5-WadN3zXMGyoCLW8_xmUldY3Q." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
    "U0m_YmjN04DJvceFICbCVQ";

  const wrongInitializationVectorToken =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "eE63cGwX4T7eSspUA72t2Q." +
    "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
    "U0m_YmjN04DJvceFICbCVQ";

  const wrongCiphertextToken =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "giYkZlt454236QV7AdREOuT0UOQrnNW1dpTna5JQpDk." +
    "U0m_YmjN04DJvceFICbCVQ";

  const wrongAuthenticationTagToken =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
    "24tpOFXtrTHSIdllxDRtlw";

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

  const compressedAttachedToken =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIn0." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA." +
    "PGfg9jnB_-hnQBGbNu8jBQ";

  const compressedDetachedToken =
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIn0." +
    "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "." +
    "PGfg9jnB_-hnQBGbNu8jBQ";

  const plaintext = Buffer.from("Live long and prosper.");

  const protectedHeader: JsonWebEncryptionHeaderParameters = { alg: "A128KW", enc: "A128CBC-HS256" };
  const protectedCompressedHeader: JsonWebEncryptionHeaderParameters = {
    alg: "A128KW",
    enc: "A128CBC-HS256",
    zip: "DEF",
  };

  const ciphertext = Buffer.from("KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY", "base64url");
  const compressedCiphertext = Buffer.from("7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA", "base64url");

  const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({ k: "GawgguFyGrWKav7AX4VKUg", kty: "oct" });

  it.each(invalidDeserializeOptions)(
    "should throw when the provided Compact JSON Web Encryption Deserialize Options is invalid.",
    async (options) => {
      const error = new TypeError("The provided Compact JSON Web Encryption Deserialize Options is invalid.");
      await expect(deserialize(attachedToken, options)).rejects.toThrow(error);
    },
  );

  it.each(invalidJsonWebKeys)(
    'should throw when the provided Compact JSON Web Encryption Deserialize Option "jsonWebKey" is invalid.',
    async (_jsonWebKey) => {
      const error = new TypeError(
        'The provided Compact JSON Web Encryption Deserialize Option "jsonWebKey" is invalid.',
      );
      await expect(deserialize(attachedToken, { jsonWebKey: _jsonWebKey })).rejects.toThrow(error);
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided Compact JSON Web Encryption Deserialize Option "expectedKeyManagementAlgorithms" is invalid.',
    async (expectedKeyManagementAlgorithms) => {
      const error = new TypeError(
        'The provided Compact JSON Web Encryption Deserialize Option "expectedKeyManagementAlgorithms" is invalid.',
      );

      await expect(deserialize(attachedToken, { expectedKeyManagementAlgorithms })).rejects.toThrow(error);
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided Compact JSON Web Encryption Deserialize Option "expectedContentEncryptionAlgorithms" is invalid.',
    async (expectedContentEncryptionAlgorithms) => {
      const error = new TypeError(
        'The provided Compact JSON Web Encryption Deserialize Option "expectedContentEncryptionAlgorithms" is invalid.',
      );

      await expect(deserialize(attachedToken, { expectedContentEncryptionAlgorithms })).rejects.toThrow(error);
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided Compact JSON Web Encryption Deserialize Option "expectedCompressionAlgorithms" is invalid.',
    async (expectedCompressionAlgorithms) => {
      const error = new TypeError(
        'The provided Compact JSON Web Encryption Deserialize Option "expectedCompressionAlgorithms" is invalid.',
      );

      await expect(deserialize(attachedToken, { expectedCompressionAlgorithms })).rejects.toThrow(error);
    },
  );

  it.each(invalidDetachedCiphertexts)(
    'should throw when the provided Compact JSON Web Encryption Deserialize Option "detachedCiphertext" is invalid.',
    async (detachedCiphertext) => {
      const error = new TypeError(
        'The provided Compact JSON Web Encryption Deserialize Option "detachedCiphertext" is invalid.',
      );

      await expect(deserialize(detachedToken, { detachedCiphertext })).rejects.toThrow(error);
    },
  );

  it.each(invalidTokens)("should throw when the provided JSON Web Encryption is invalid.", async (token) => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(token)).rejects.toThrow(error);
  });

  it("should throw when deserializing a Detached Compact JSON Web Encryption Token and not providing a Detached Ciphertext.", async () => {
    const error = new InvalidJsonWebEncryptionError("The JSON Web Encryption requires a valid Ciphertext.");
    await expect(deserialize(detachedToken)).rejects.toThrow(error);
  });

  it("should throw when providing a Detached Ciphertext for a Compact JSON Web Encryption Token that already has a Ciphertext.", async () => {
    const error = new InvalidJsonWebEncryptionError(
      "The provided JSON Web Encryption already has a defined Ciphertext.",
    );

    await expect(deserialize(attachedToken, { detachedCiphertext: ciphertext })).rejects.toThrow(error);
  });

  it("should throw when the JSON Web Encryption Key Management Algorithm of the Compact JSON Web Encryption Token is unexpected.", async () => {
    const error = new InvalidJsonWebEncryptionError('Unexpected Key Management Algorithm "A128KW".');
    await expect(deserialize(attachedToken, { expectedKeyManagementAlgorithms: ["A256KW"] })).rejects.toThrow(error);
  });

  it("should throw when the JSON Web Encryption Content Encryption Algorithm of the Compact JSON Web Encryption Token is unexpected.", async () => {
    const error = new InvalidJsonWebEncryptionError('Unexpected Content Encryption Algorithm "A128CBC-HS256".');

    await expect(
      deserialize(attachedToken, { expectedContentEncryptionAlgorithms: ["A256CBC-HS512"] }),
    ).rejects.toThrow(error);
  });

  it("should throw when the JSON Web Encryption Compression Algorithm of the Compact JSON Web Encryption Token is unexpected.", async () => {
    const error = new InvalidJsonWebEncryptionError('Unexpected Compression Algorithm "".');
    await expect(deserialize(attachedToken, { expectedCompressionAlgorithms: ["DEF"] })).rejects.toThrow(error);
  });

  it("should throw when the provided Encrypted Key fails to deserialize the provided Compact JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongEncryptedKeyToken, { jsonWebKey })).rejects.toThrow(error);
  });

  it("should throw when the provided Initialization Vector fails to deserialize the provided Compact JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongInitializationVectorToken, { jsonWebKey })).rejects.toThrow(error);
  });

  it("should throw when the provided Ciphertext fails to deserialize the provided Compact JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongCiphertextToken, { jsonWebKey })).rejects.toThrow(error);
  });

  it("should throw when the provided Authentication Tag fails to deserialize the provided Compact JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongAuthenticationTagToken, { jsonWebKey })).rejects.toThrow(error);
  });

  it("should return the deserialized Compact JSON Web Encryption from an Attached Compact JSON Web Encryption Token.", async () => {
    await expect(deserialize(attachedToken, { jsonWebKey })).resolves.toStrictEqual<CompactJsonWebEncryption>({
      plaintext,
      protectedHeader: new JsonWebEncryptionHeader(protectedHeader),
    });
  });

  it("should return the deserialized Compact JSON Web Encryption from a Detached Compact JSON Web Encryption Token.", async () => {
    await expect(
      deserialize(detachedToken, { detachedCiphertext: ciphertext, jsonWebKey }),
    ).resolves.toStrictEqual<CompactJsonWebEncryption>({
      plaintext,
      protectedHeader: new JsonWebEncryptionHeader(protectedHeader),
    });
  });

  it("should return the deserialized Compact JSON Web Encryption from a Compressed Attached Compact JSON Web Encryption Token.", async () => {
    await expect(deserialize(compressedAttachedToken, { jsonWebKey })).resolves.toStrictEqual<CompactJsonWebEncryption>(
      { plaintext, protectedHeader: new JsonWebEncryptionHeader(protectedCompressedHeader) },
    );
  });

  it("should return the deserialized Compact JSON Web Encryption from a Compressed Detached Compact JSON Web Encryption Token.", async () => {
    await expect(
      deserialize(compressedDetachedToken, { detachedCiphertext: compressedCiphertext, jsonWebKey }),
    ).resolves.toStrictEqual<CompactJsonWebEncryption>({
      plaintext,
      protectedHeader: new JsonWebEncryptionHeader(protectedCompressedHeader),
    });
  });
});
