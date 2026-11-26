import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import { JsonWebSignatureHeader } from "../../../header/jsonwebsignature.header.ts";
import type { FlattenedJsonWebSignatureToken } from "../flattened.jsonwebsignature.token.ts";
import type { FlattenedJsonWebSignature } from "../flattened.jsonwebsignature.ts";
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
  ["A128KW"],
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

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, "", Symbol("a"), Buffer, Buffer.alloc(1), () => 1, []];

describe("deserialize()", () => {
  const wrongSignatureToken: FlattenedJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
    signature: "oYyAwnx7D5WIo3L1WWx_zBSNX12nH8lwXQHgpPiApSk",
  };

  // #region Unencoded Attached Token Without Dot
  const unencodedProtectedAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const missingUnencodedProtectedAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    protected: "eyJhbGciOiJIUzI1NiJ9",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const badUnencodedUnprotectedAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { alg: "HS256", b64: false, crit: ["b64"], kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const missingUnencodedUnprotectedAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { alg: "HS256", kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const unencodedFullAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const badUnencodedFullAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { b64: false, crit: ["b64"], kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    protected: "eyJhbGciOiJIUzI1NiJ9",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const missingUnencodedFullAttachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    protected: "eyJhbGciOiJIUzI1NiJ9",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };
  // #endregion
  // #region Unencoded Detached Token Without Dot
  const unencodedProtectedDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const missingUnencodedProtectedDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    protected: "eyJhbGciOiJIUzI1NiJ9",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const badUnencodedUnprotectedDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { alg: "HS256", b64: false, crit: ["b64"], kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const missingUnencodedUnprotectedDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { alg: "HS256", kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const unencodedFullDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const badUnencodedFullDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { b64: false, crit: ["b64"], kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    protected: "eyJhbGciOiJIUzI1NiJ9",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };

  const missingUnencodedFullDetachedTokenWithoutDot: FlattenedJsonWebSignatureToken = {
    header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    protected: "eyJhbGciOiJIUzI1NiJ9",
    signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
  };
  // #endregion
  // #region Unencoded Detached Token With Dot
  const unencodedProtectedDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
    signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
  };

  const missingUnencodedProtectedDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    protected: "eyJhbGciOiJIUzI1NiJ9",
    signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
  };

  const badUnencodedUnprotectedDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    header: { alg: "HS256", b64: false, crit: ["b64"], kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
  };

  const missingUnencodedUnprotectedDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    header: { alg: "HS256", kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
  };

  const unencodedFullDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
    signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
  };

  const badUnencodedFullDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    header: { b64: false, crit: ["b64"], kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    protected: "eyJhbGciOiJIUzI1NiJ9",
    signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
  };

  const missingUnencodedFullDetachedTokenWithDot: FlattenedJsonWebSignatureToken = {
    header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
    protected: "eyJhbGciOiJIUzI1NiJ9",
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

  it.each(invalidDeserializeOptions)(
    "should throw when the provided Flattened JSON Web Signature Deserialize Options is invalid.",
    async (options) => {
      const error = new TypeError("The provided Flattened JSON Web Signature Deserialize Options is invalid.");
      await expect(deserialize(unencodedProtectedAttachedTokenWithoutDot, options)).rejects.toThrow(error);
    },
  );

  it.each(invalidJsonWebKeys)(
    'should throw when the provided Flattened JSON Web Signature Deserialize Option "jsonWebKey" is invalid.',
    async (_jsonWebKey) => {
      const error = new TypeError(
        'The provided Flattened JSON Web Signature Deserialize Option "jsonWebKey" is invalid.',
      );

      await expect(deserialize(unencodedProtectedAttachedTokenWithoutDot, { jsonWebKey: _jsonWebKey })).rejects.toThrow(
        error,
      );
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided Flattened JSON Web Signature Deserialize Option "expectedDigitalSignatureAlgorithms" is invalid.',
    async (expectedDigitalSignatureAlgorithms) => {
      const error = new TypeError(
        'The provided Flattened JSON Web Signature Deserialize Option "expectedDigitalSignatureAlgorithms" is invalid.',
      );

      await expect(
        deserialize(unencodedProtectedAttachedTokenWithoutDot, { expectedDigitalSignatureAlgorithms }),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidDetachedPayloads)(
    'should throw when the provided Flattened JSON Web Signature Deserialize Option "detachedPayload" is invalid.',
    async (detachedPayload) => {
      const error = new TypeError(
        'The provided Flattened JSON Web Signature Deserialize Option "detachedPayload" is invalid.',
      );

      await expect(deserialize(unencodedProtectedAttachedTokenWithoutDot, { detachedPayload })).rejects.toThrow(error);
    },
  );

  it.each(invalidTokens)(
    "should throw when the provided Flattened JSON Web Signature Token is invalid.",
    async (token) => {
      const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
      await expect(deserialize(token)).rejects.toThrow(error);
    },
  );

  it("should throw when deserializing a Detached Flattened JSON Web Signature Token and not providing a Detached Payload.", async () => {
    const error = new InvalidJsonWebSignatureError("The JSON Web Signature requires a valid Payload.");
    await expect(deserialize(unencodedProtectedDetachedTokenWithoutDot)).rejects.toThrow(error);
  });

  it("should throw when providing a Detached Payload for a Flattened JSON Web Signature Token that already has a Payload.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature already has a defined Payload.");

    await expect(
      deserialize(unencodedProtectedAttachedTokenWithoutDot, { detachedPayload: payloadWithoutDot }),
    ).rejects.toThrow(error);
  });

  it("should throw when the Digital Signature Algorithm of the Flattened JSON Web Signature Token is unexpected.", async () => {
    const error = new InvalidJsonWebSignatureError('Unexpected Digital Signature Algorithm "HS256".');

    await expect(
      deserialize(unencodedProtectedAttachedTokenWithoutDot, { expectedDigitalSignatureAlgorithms: ["HS512"] }),
    ).rejects.toThrow(error);
  });

  it("should throw when the provided Signature fails to deserialize the provided Flattened JSON Web Signature Token.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    await expect(deserialize(wrongSignatureToken, { jsonWebKey })).rejects.toThrow(error);
  });

  it("should return the deserialized Flattened JSON Web Signature from a Protected Attached Unencoded Token without a dot.", async () => {
    await expect(
      deserialize(unencodedProtectedAttachedTokenWithoutDot, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebSignature>({
      header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: unencodedProtectedHeader,
      unprotectedHeader: null,
    });
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected Attached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    await expect(deserialize(missingUnencodedProtectedAttachedTokenWithoutDot, { jsonWebKey })).rejects.toThrow(error);
  });

  it("should throw when deserializing a Flattened JSON Web Signature from an Unprotected Attached Unencoded Token without a dot.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    await expect(deserialize(badUnencodedUnprotectedAttachedTokenWithoutDot, { jsonWebKey })).rejects.toThrow(error);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Attached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(deserialize(missingUnencodedUnprotectedAttachedTokenWithoutDot, { jsonWebKey })).rejects.toThrow(
      error,
    );
  });

  it("should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Attached Unencoded Token without a dot.", async () => {
    await expect(
      deserialize(unencodedFullAttachedTokenWithoutDot, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebSignature>({
      header: new JsonWebSignatureHeader({
        ...unencodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: unencodedProtectedHeader,
      unprotectedHeader,
    });
  });

  it("should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Attached Unencoded Token without a dot.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    await expect(deserialize(badUnencodedFullAttachedTokenWithoutDot, { jsonWebKey })).rejects.toThrow(error);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Attached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    await expect(deserialize(missingUnencodedFullAttachedTokenWithoutDot, { jsonWebKey })).rejects.toThrow(error);
  });

  it("should return the deserialized Flattened JSON Web Signature from a Protected Detached Unencoded Token without a dot.", async () => {
    await expect(
      deserialize(unencodedProtectedDetachedTokenWithoutDot, { detachedPayload: payloadWithoutDot, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebSignature>({
      header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: unencodedProtectedHeader,
      unprotectedHeader: null,
    });
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected Detached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedProtectedDetachedTokenWithoutDot, { detachedPayload: payloadWithoutDot, jsonWebKey }),
    ).rejects.toThrow(error);
  });

  it("should throw when deserializing a Flattened JSON Web Signature from an Unprotected Detached Unencoded Token without a dot.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(badUnencodedUnprotectedDetachedTokenWithoutDot, { detachedPayload: payloadWithoutDot, jsonWebKey }),
    ).rejects.toThrow(error);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Detached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedUnprotectedDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        jsonWebKey,
      }),
    ).rejects.toThrow(error);
  });

  it("should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token without a dot.", async () => {
    await expect(
      deserialize(unencodedFullDetachedTokenWithoutDot, { detachedPayload: payloadWithoutDot, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebSignature>({
      header: new JsonWebSignatureHeader({
        ...unencodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: unencodedProtectedHeader,
      unprotectedHeader,
    });
  });

  it("should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token without a dot.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(badUnencodedFullDetachedTokenWithoutDot, { detachedPayload: payloadWithoutDot, jsonWebKey }),
    ).rejects.toThrow(error);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedFullDetachedTokenWithoutDot, { detachedPayload: payloadWithoutDot, jsonWebKey }),
    ).rejects.toThrow(error);
  });

  it("should return the deserialized Flattened JSON Web Signature from a Protected Detached Unencoded Token with a dot.", async () => {
    await expect(
      deserialize(unencodedProtectedDetachedTokenWithDot, { detachedPayload: payloadWithDot, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebSignature>({
      header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: payloadWithDot,
      protectedHeader: unencodedProtectedHeader,
      unprotectedHeader: null,
    });
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected Detached Unencoded Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedProtectedDetachedTokenWithDot, { detachedPayload: payloadWithDot, jsonWebKey }),
    ).rejects.toThrow(error);
  });

  it("should throw when deserializing a Flattened JSON Web Signature from an Unprotected Detached Unencoded Token with a dot.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(badUnencodedUnprotectedDetachedTokenWithDot, { detachedPayload: payloadWithDot, jsonWebKey }),
    ).rejects.toThrow(error);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from an Unprotected Detached Unencoded Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedUnprotectedDetachedTokenWithDot, { detachedPayload: payloadWithDot, jsonWebKey }),
    ).rejects.toThrow(error);
  });

  it("should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token with a dot.", async () => {
    await expect(
      deserialize(unencodedFullDetachedTokenWithDot, { detachedPayload: payloadWithDot, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebSignature>({
      header: new JsonWebSignatureHeader({
        ...unencodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: payloadWithDot,
      protectedHeader: unencodedProtectedHeader,
      unprotectedHeader,
    });
  });

  it("should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token with a dot.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(badUnencodedFullDetachedTokenWithDot, { detachedPayload: payloadWithDot, jsonWebKey }),
    ).rejects.toThrow(error);
  });

  it('should throw when deserializing a Flattened JSON Web Signature from a Protected and Unprotected Detached Unencoded Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedFullDetachedTokenWithDot, { detachedPayload: payloadWithDot, jsonWebKey }),
    ).rejects.toThrow(error);
  });

  it("should return the deserialized Flattened JSON Web Signature from a Protected Attached Encoded Token without a dot.", async () => {
    await expect(
      deserialize(encodedProtectedAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebSignature>({
      header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: encodedProtectedHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Signature from an Unprotected Attached Encoded Token without a dot.", async () => {
    await expect(
      deserialize(encodedUnprotectedAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebSignature>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: null,
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
    });
  });

  it("should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Attached Encoded Token without a dot.", async () => {
    await expect(
      deserialize(encodedFullAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebSignature>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: encodedProtectedHeader,
      unprotectedHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Signature from a Protected Detached Encoded Token without a dot.", async () => {
    await expect(
      deserialize(encodedProtectedDetachedToken, { detachedPayload: payloadWithoutDot, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebSignature>({
      header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: encodedProtectedHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Signature from an Unprotected Detached Encoded Token without a dot.", async () => {
    await expect(
      deserialize(encodedUnprotectedDetachedToken, { detachedPayload: payloadWithoutDot, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebSignature>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: null,
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
    });
  });

  it("should return the deserialized Flattened JSON Web Signature from a Protected and Unprotected Detached Encoded Token without a dot.", async () => {
    await expect(
      deserialize(encodedFullDetachedToken, { detachedPayload: payloadWithoutDot, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebSignature>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: encodedProtectedHeader,
      unprotectedHeader,
    });
  });
});
