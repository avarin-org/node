import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJoseHeaderError } from "../../../../errors/invalid-jose-header.error.ts";
import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import type { FlattenedJsonWebSignatureToken } from "../flattened.jsonwebsignature.token.ts";
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

const invalidHeaders: any[] = [
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

const invalidUnprotectedHeaders: any[] = [
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
  // #region Unencoded Attached Token Without Dot
  const unencodedProtectedAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const unencodedFullAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };
  // #endregion
  // #region Unencoded Detached Token Without Dot
  const unencodedProtectedDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const unencodedFullDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };
  // #endregion
  // #region Unencoded Detached Token With Dot
  const unencodedProtectedDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
    signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
  };

  const unencodedFullDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
    signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
  };
  // #endregion
  // #region Encoded Attached Token
  const encodedProtectedAttachedToken: FlattenedJsonWebSignatureToken = {
    payload: "eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0",
    protected: "eyJhbGciOiJIUzI1NiJ9",
    signature: "hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA",
  };

  const encodedUnprotectedAttachedToken: FlattenedJsonWebSignatureToken = {
    header: { alg: "HS256", kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    payload: "eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0",
    signature: "iRxcRLDYSMrd3ZlYZ_tUXP8pRAShmoErGTo4sEsew3U",
  };

  const encodedFullAttachedToken: FlattenedJsonWebSignatureToken = {
    header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    payload: "eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0",
    protected: "eyJhbGciOiJIUzI1NiJ9",
    signature: "hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA",
  };
  // #endregion
  // #region Encoded Detached Token
  const encodedProtectedDetachedToken: FlattenedJsonWebSignatureToken = {
    protected: "eyJhbGciOiJIUzI1NiJ9",
    signature: "hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA",
  };

  const encodedUnprotectedDetachedToken: FlattenedJsonWebSignatureToken = {
    header: { alg: "HS256", kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    signature: "iRxcRLDYSMrd3ZlYZ_tUXP8pRAShmoErGTo4sEsew3U",
  };

  const encodedFullDetachedToken: FlattenedJsonWebSignatureToken = {
    header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    protected: "eyJhbGciOiJIUzI1NiJ9",
    signature: "hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA",
  };
  // #endregion

  const unencodedProtectedHeader: Partial<JsonWebSignatureHeaderParameters> = {
    alg: "HS256",
    b64: false,
    crit: ["b64"],
  };

  const encodedProtectedHeader: Partial<JsonWebSignatureHeaderParameters> = { alg: "HS256" };
  const unprotectedHeader: Partial<JsonWebSignatureHeaderParameters> = { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" };

  const payloadWithoutDot = Buffer.from('{"iat": 1723010455, "sub": "078BWDDXasdcg8"}', "utf8");
  const payloadWithDot = Buffer.from("$.02", "utf8");

  const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
    k: "qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ",
    kty: "oct",
  });

  it.each(invalidPayloads)("should throw when the provided Payload is invalid.", async (payload) => {
    const error = new TypeError("The provided Payload is invalid.");

    await expect(serialize(payload, { protectedHeader: encodedProtectedHeader, unprotectedHeader })).rejects.toThrow(
      error,
    );
  });

  it.each(invalidHeaders)("should throw when the provided JSON Web Signature Headers is invalid.", async (headers) => {
    const error = new TypeError("The provided JSON Web Signature Headers is invalid.");
    await expect(serialize(payloadWithoutDot, headers)).rejects.toThrow(error);
  });

  it.each(invalidProtectedHeaders)(
    "should throw when the provided JSON Web Signature Protected Header is invalid.",
    async (protectedHeader) => {
      const error = new TypeError("The provided JSON Web Signature Protected Header is invalid.");
      await expect(serialize(payloadWithoutDot, { protectedHeader, unprotectedHeader })).rejects.toThrow(error);
    },
  );

  it.each(invalidUnprotectedHeaders)(
    "should throw when the provided JSON Web Signature Unprotected Header is invalid.",
    async (_unprotectedHeader) => {
      const error = new TypeError("The provided JSON Web Signature Unprotected Header is invalid.");

      await expect(
        serialize(payloadWithoutDot, {
          protectedHeader: encodedProtectedHeader,
          unprotectedHeader: _unprotectedHeader,
        }),
      ).rejects.toThrow(error);
    },
  );

  it("should throw when no JSON Web Signature Header is provided.", async () => {
    const error = new TypeError("Missing at least one required JSON Web Signature Header.");
    await expect(serialize(payloadWithoutDot, {})).rejects.toThrow(error);
  });

  it("should throw when there are repeated JSON Web Signature Header Parameters.", async () => {
    const error = new TypeError("Cannot have repeated JSON Web Signature Header Parameters.");

    await expect(
      serialize(payloadWithoutDot, {
        protectedHeader: encodedProtectedHeader,
        unprotectedHeader: encodedProtectedHeader,
      }),
    ).rejects.toThrow(error);
  });

  it('should throw if the JOSE Header Parameter "crit" is present in the Unprotected Header.', async () => {
    const error = new InvalidJoseHeaderError('Invalid JSON Web Signature Unprotected Header Parameter "crit".');

    await expect(
      serialize(payloadWithoutDot, {
        protectedHeader: encodedProtectedHeader,
        unprotectedHeader: { crit: ["foo"], foo: "foo" },
      }),
    ).rejects.toThrow(error);
  });

  it('should throw if the JOSE Header Parameter "b64" is present in the Unprotected Header.', async () => {
    const error = new InvalidJoseHeaderError('Invalid JSON Web Signature Unprotected Header Parameter "b64".');

    await expect(
      serialize(payloadWithoutDot, { protectedHeader: encodedProtectedHeader, unprotectedHeader: { b64: false } }),
    ).rejects.toThrow(error);
  });

  it.each(invalidSerializeOptions)(
    "should throw when the provided Flattened JSON Web Signature Serialize Options is invalid.",
    async (options) => {
      const error = new TypeError("The provided Flattened JSON Web Signature Serialize Options is invalid.");

      await expect(
        serialize(payloadWithoutDot, { protectedHeader: encodedProtectedHeader, unprotectedHeader }, options),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidJsonWebKeys)(
    'should throw when the provided Flattened JSON Web Signature Serialize Option "jsonWebKey" is invalid.',
    async (_jsonWebKey) => {
      const error = new TypeError(
        'The provided Flattened JSON Web Signature Serialize Option "jsonWebKey" is invalid.',
      );

      await expect(
        serialize(
          payloadWithoutDot,
          { protectedHeader: encodedProtectedHeader, unprotectedHeader },
          { jsonWebKey: _jsonWebKey },
        ),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidDetacheds)(
    'should throw when the provided Flattened JSON Web Signature Serialize Option "detached" is invalid.',
    async (detached) => {
      const error = new TypeError('The provided Flattened JSON Web Signature Serialize Option "detached" is invalid.');

      await expect(
        serialize(payloadWithoutDot, { protectedHeader: encodedProtectedHeader, unprotectedHeader }, { detached }),
      ).rejects.toThrow(error);
    },
  );

  it("should throw when serializing an Attached Unencoded Payload with a dot in its contents.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided Unencoded Payload cannot be serialized.");

    await expect(serialize(payloadWithDot, { protectedHeader: unencodedProtectedHeader })).rejects.toThrow(error);

    await expect(
      serialize(payloadWithDot, { protectedHeader: unencodedProtectedHeader }, { detached: false, jsonWebKey }),
    ).rejects.toThrow(error);
  });

  it("should serialize a Flattened JSON Web Signature Protected Attached Unencoded Token without a dot.", async () => {
    await expect(
      serialize(payloadWithoutDot, { protectedHeader: unencodedProtectedHeader }, { jsonWebKey }),
    ).resolves.toStrictEqual(unencodedProtectedAttachedTokenWithoutDot);
  });

  it("should serialize a Flattened JSON Web Signature Protected and Unprotected Attached Unencoded Token without a dot.", async () => {
    await expect(
      serialize(payloadWithoutDot, { protectedHeader: unencodedProtectedHeader, unprotectedHeader }, { jsonWebKey }),
    ).resolves.toStrictEqual(unencodedFullAttachedTokenWithoutDot);
  });

  it("should serialize a Flattened JSON Web Signature Protected Detached Unencoded Token without a dot.", async () => {
    await expect(
      serialize(payloadWithoutDot, { protectedHeader: unencodedProtectedHeader }, { detached: true, jsonWebKey }),
    ).resolves.toStrictEqual(unencodedProtectedDetachedTokenWithoutDot);
  });

  it("should serialize a Flattened JSON Web Signature Protected and Unprotected Detached Unencoded Token without a dot.", async () => {
    await expect(
      serialize(
        payloadWithoutDot,
        { protectedHeader: unencodedProtectedHeader, unprotectedHeader },
        { detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(unencodedFullDetachedTokenWithoutDot);
  });

  it("should serialize a Flattened JSON Web Signature Protected Detached Unencoded Token with a dot.", async () => {
    await expect(
      serialize(payloadWithDot, { protectedHeader: unencodedProtectedHeader }, { detached: true, jsonWebKey }),
    ).resolves.toStrictEqual(unencodedProtectedDetachedTokenWithDot);
  });

  it("should serialize a Flattened JSON Web Signature Protected and Unprotected Detached Unencoded Token with a dot.", async () => {
    await expect(
      serialize(
        payloadWithDot,
        { protectedHeader: unencodedProtectedHeader, unprotectedHeader },
        { detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(unencodedFullDetachedTokenWithDot);
  });

  it("should serialize a Flattened JSON Web Signature Protected Attached Encoded Token without a dot.", async () => {
    await expect(
      serialize(payloadWithoutDot, { protectedHeader: encodedProtectedHeader }, { jsonWebKey }),
    ).resolves.toStrictEqual(encodedProtectedAttachedToken);
  });

  it("should serialize a Flattened JSON Web Signature Unprotected Attached Encoded Token without a dot.", async () => {
    await expect(
      serialize(
        payloadWithoutDot,
        { unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader } },
        { jsonWebKey },
      ),
    ).resolves.toStrictEqual(encodedUnprotectedAttachedToken);
  });

  it("should serialize a Flattened JSON Web Signature Protected and Unprotected Attached Encoded Token without a dot.", async () => {
    await expect(
      serialize(payloadWithoutDot, { protectedHeader: encodedProtectedHeader, unprotectedHeader }, { jsonWebKey }),
    ).resolves.toStrictEqual(encodedFullAttachedToken);
  });

  it("should serialize a Flattened JSON Web Signature Protected Detached Encoded Token without a dot.", async () => {
    await expect(
      serialize(payloadWithoutDot, { protectedHeader: encodedProtectedHeader }, { detached: true, jsonWebKey }),
    ).resolves.toStrictEqual(encodedProtectedDetachedToken);
  });

  it("should serialize a Flattened JSON Web Signature Unprotected Detached Encoded Token without a dot.", async () => {
    await expect(
      serialize(
        payloadWithoutDot,
        { unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader } },
        { detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(encodedUnprotectedDetachedToken);
  });

  it("should serialize a Flattened JSON Web Signature Protected and Unprotected Detached Encoded Token without a dot.", async () => {
    await expect(
      serialize(
        payloadWithoutDot,
        { protectedHeader: encodedProtectedHeader, unprotectedHeader },
        { detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(encodedFullDetachedToken);
  });
});
