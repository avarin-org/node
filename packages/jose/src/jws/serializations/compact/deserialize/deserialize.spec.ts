import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import { JsonWebSignatureHeader } from "../../../header/jsonwebsignature.header.ts";
import type { CompactJsonWebSignature } from "../compact.jsonwebsignature.ts";
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

const invalidDetachedPayloads: any[] = [
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
  const wrongSignatureToken =
    "eyJhbGciOiJIUzI1NiJ9." +
    "eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0." +
    "oYyAwnx7D5WIo3L1WWx_zBSNX12nH8lwXQHgpPiApSk";

  const unencodedAttachedTokenWithoutDot =
    "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19." +
    '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}.' +
    "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA";

  const unencodedDetachedTokenWithoutDot =
    "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA";

  const unencodedDetachedTokenWithDot =
    "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY";

  const encodedAttachedToken =
    "eyJhbGciOiJIUzI1NiJ9." +
    "eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0." +
    "hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA";

  const encodedDetachedToken = "eyJhbGciOiJIUzI1NiJ9..hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA";

  const unencodedProtectedHeader: JsonWebSignatureHeaderParameters = { alg: "HS256", b64: false, crit: ["b64"] };
  const encodedProtectedHeader: JsonWebSignatureHeaderParameters = { alg: "HS256" };

  const payloadWithoutDot = Buffer.from('{"iat": 1723010455, "sub": "078BWDDXasdcg8"}', "utf8");
  const payloadWithDot = Buffer.from("$.02", "utf8");

  const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
    k: "qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ",
    kty: "oct",
  });

  it.each(invalidDeserializeOptions)(
    "should throw when the provided Compact JSON Web Signature Deserialize Options is invalid.",
    async (options) => {
      const error = new TypeError("The provided Compact JSON Web Signature Deserialize Options is invalid.");
      await expect(deserialize(encodedAttachedToken, options)).rejects.toThrow(error);
    },
  );

  it.each(invalidJsonWebKeys)(
    'should throw when the provided Compact JSON Web Signature Deserialize Option "jsonWebKey" is invalid.',
    async (_jsonWebKey) => {
      const error = new TypeError(
        'The provided Compact JSON Web Signature Deserialize Option "jsonWebKey" is invalid.',
      );
      await expect(deserialize(encodedAttachedToken, { jsonWebKey: _jsonWebKey })).rejects.toThrow(error);
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided Compact JSON Web Signature Deserialize Option "expectedDigitalSignatureAlgorithms" is invalid.',
    async (expectedDigitalSignatureAlgorithms) => {
      const error = new TypeError(
        'The provided Compact JSON Web Signature Deserialize Option "expectedDigitalSignatureAlgorithms" is invalid.',
      );

      await expect(deserialize(encodedAttachedToken, { expectedDigitalSignatureAlgorithms })).rejects.toThrow(error);
    },
  );

  it.each(invalidDetachedPayloads)(
    'should throw when the provided Compact JSON Web Signature Deserialize Option "detachedPayload" is invalid.',
    async (detachedPayload) => {
      const error = new TypeError(
        'The provided Compact JSON Web Signature Deserialize Option "detachedPayload" is invalid.',
      );

      await expect(deserialize(encodedDetachedToken, { detachedPayload })).rejects.toThrow(error);
    },
  );

  it.each(invalidTokens)("should throw when the provided JSON Web Signature is invalid.", async (token) => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    await expect(deserialize(token)).rejects.toThrow(error);
  });

  it("should throw when deserializing a Detached Compact JSON Web Signature Token and not providing a Detached Payload.", async () => {
    const error = new InvalidJsonWebSignatureError("The JSON Web Signature requires a valid Payload.");
    await expect(deserialize(encodedDetachedToken)).rejects.toThrow(error);
  });

  it("should throw when providing a Detached Payload for a Compact JSON Web Signature Token that already has a Payload.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature already has a defined Payload.");
    await expect(deserialize(encodedAttachedToken, { detachedPayload: payloadWithoutDot })).rejects.toThrow(error);
  });

  it("should throw when the JSON Web Signature Digital Signature Algorithm of the Compact JSON Web Signature Token is unexpected.", async () => {
    const error = new InvalidJsonWebSignatureError('Unexpected Digital Signature Algorithm "HS256".');
    await expect(deserialize(encodedAttachedToken, { expectedDigitalSignatureAlgorithms: ["HS512"] })).rejects.toThrow(
      error,
    );
  });

  it("should throw when the provided Signature fails to deserialize the provided Compact JSON Web Signature Token.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    await expect(deserialize(wrongSignatureToken, { jsonWebKey })).rejects.toThrow(error);
  });

  it("should return the deserialized Compact JSON Web Signature from an Attached Unencoded Compact JSON Web Signature Token without a dot.", async () => {
    await expect(
      deserialize(unencodedAttachedTokenWithoutDot, { jsonWebKey }),
    ).resolves.toStrictEqual<CompactJsonWebSignature>({
      header: new JsonWebSignatureHeader(unencodedProtectedHeader),
      payload: payloadWithoutDot,
    });
  });

  it("should return the deserialized Compact JSON Web Signature from a Detached Unencoded Compact JSON Web Signature Token without a dot.", async () => {
    await expect(
      deserialize(unencodedDetachedTokenWithoutDot, { detachedPayload: payloadWithoutDot, jsonWebKey }),
    ).resolves.toStrictEqual<CompactJsonWebSignature>({
      header: new JsonWebSignatureHeader(unencodedProtectedHeader),
      payload: payloadWithoutDot,
    });
  });

  it("should return the deserialized Compact JSON Web Signature from a Detached Unencoded Compact JSON Web Signature Token with a dot.", async () => {
    await expect(
      deserialize(unencodedDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        jsonWebKey: new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
          k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
          kty: "oct",
        }),
      }),
    ).resolves.toStrictEqual<CompactJsonWebSignature>({
      header: new JsonWebSignatureHeader(unencodedProtectedHeader),
      payload: payloadWithDot,
    });
  });

  it("should return the deserialized Compact JSON Web Signature from an Attached Encoded Compact JSON Web Signature Token without a dot.", async () => {
    await expect(deserialize(encodedAttachedToken, { jsonWebKey })).resolves.toStrictEqual<CompactJsonWebSignature>({
      header: new JsonWebSignatureHeader(encodedProtectedHeader),
      payload: payloadWithoutDot,
    });
  });

  it("should return the deserialized Compact JSON Web Signature from a Detached Encoded Compact JSON Web Signature Token without a dot.", async () => {
    await expect(
      deserialize(encodedDetachedToken, { detachedPayload: payloadWithoutDot, jsonWebKey }),
    ).resolves.toStrictEqual<CompactJsonWebSignature>({
      header: new JsonWebSignatureHeader(encodedProtectedHeader),
      payload: payloadWithoutDot,
    });
  });
});
