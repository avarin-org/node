import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/index.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import { serialize } from "./serialize.ts";

const invalidPayloads: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  () => 1,
  {},
  [],
  Buffer.alloc(0),
];

const invalidProtectedHeaders: any[] = [
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
];

const invalidSerializeOptions: any[] = [null, true, 1, 1.2, 1n, "a", Symbol("a"), Buffer, Buffer.alloc(1), () => 1, []];

const invalidJsonWebKeys: any[] = [
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
];

const invalidDetacheds: any[] = [
  undefined,
  null,
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

describe("serialize()", () => {
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

  const payloadWithoutDot = Buffer.from('{"iat": 1723010455, "sub": "078BWDDXasdcg8"}', "utf8");
  const payloadWithDot = Buffer.from("$.02", "utf8");

  const unencodedProtectedHeader: JsonWebSignatureHeaderParameters = { alg: "HS256", b64: false, crit: ["b64"] };
  const encodedProtectedHeader: JsonWebSignatureHeaderParameters = { alg: "HS256" };

  const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
    k: "qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ",
    kty: "oct",
  });

  it.each(invalidPayloads)("should throw when the provided Payload is invalid.", async (_payload) => {
    const error = new TypeError("The provided Payload is invalid.");
    await expect(serialize(_payload, encodedProtectedHeader)).rejects.toThrow(error);
  });

  it.each(invalidProtectedHeaders)(
    "should throw when the provided JSON Web Signature Protected Header is invalid.",
    async (_protectedHeader) => {
      const error = new TypeError("The provided JSON Web Signature Protected Header is invalid.");
      await expect(serialize(payloadWithoutDot, _protectedHeader)).rejects.toThrow(error);
    },
  );

  it.each(invalidSerializeOptions)(
    "should throw when the provided Compact JSON Web Signature Serialize Options is invalid.",
    async (options) => {
      const error = new TypeError("The provided Compact JSON Web Signature Serialize Options is invalid.");
      await expect(serialize(payloadWithoutDot, encodedProtectedHeader, options)).rejects.toThrow(error);
    },
  );

  it.each(invalidJsonWebKeys)(
    'should throw when the provided Compact JSON Web Signature Serialize Option "jsonWebKey" is invalid.',
    async (_jsonWebKey) => {
      const error = new TypeError('The provided Compact JSON Web Signature Serialize Option "jsonWebKey" is invalid.');
      await expect(serialize(payloadWithoutDot, encodedProtectedHeader, { jsonWebKey: _jsonWebKey })).rejects.toThrow(
        error,
      );
    },
  );

  it.each(invalidDetacheds)(
    'should throw when the provided Compact JSON Web Signature Serialize Option "detached" is invalid.',
    async (detached) => {
      const error = new TypeError('The provided Compact JSON Web Signature Serialize Option "detached" is invalid.');
      await expect(serialize(payloadWithoutDot, encodedProtectedHeader, { detached })).rejects.toThrow(error);
    },
  );

  it("should throw when serializing an Attached Unencoded Payload with a dot in its contents.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided Unencoded Payload cannot be serialized.");

    await expect(serialize(payloadWithDot, unencodedProtectedHeader)).rejects.toThrow(error);
    await expect(serialize(payloadWithDot, unencodedProtectedHeader, { detached: false, jsonWebKey })).rejects.toThrow(
      error,
    );
  });

  it("should serialize a Compact JSON Web Signature Attached Unencoded Token without a dot.", async () => {
    await expect(serialize(payloadWithoutDot, unencodedProtectedHeader, { jsonWebKey })).resolves.toStrictEqual(
      unencodedAttachedTokenWithoutDot,
    );
  });

  it("should serialize a Compact JSON Web Signature Detached Unencoded Token without a dot.", async () => {
    await expect(
      serialize(payloadWithoutDot, unencodedProtectedHeader, { detached: true, jsonWebKey }),
    ).resolves.toStrictEqual(unencodedDetachedTokenWithoutDot);
  });

  it("should serialize a Compact JSON Web Signature Detached Unencoded Token with a dot.", async () => {
    await expect(
      serialize(payloadWithDot, unencodedProtectedHeader, {
        detached: true,
        jsonWebKey: new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
          k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
          kty: "oct",
        }),
      }),
    ).resolves.toStrictEqual(unencodedDetachedTokenWithDot);
  });

  it("should serialize a Compact JSON Web Signature Attached Encoded Token without a dot.", async () => {
    await expect(serialize(payloadWithoutDot, encodedProtectedHeader, { jsonWebKey })).resolves.toStrictEqual(
      encodedAttachedToken,
    );
  });

  it("should serialize a Compact JSON Web Signature Detached Encoded Token without a dot.", async () => {
    await expect(
      serialize(payloadWithoutDot, encodedProtectedHeader, { detached: true, jsonWebKey }),
    ).resolves.toStrictEqual(encodedDetachedToken);
  });
});
