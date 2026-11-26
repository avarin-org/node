import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJsonWebKeyError } from "../../../../errors/invalid-jsonwebkey.error.ts";
import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import { JsonWebSignatureHeader } from "../../../header/jsonwebsignature.header.ts";
import type { GeneralJsonWebSignatureToken } from "../general.jsonwebsignature.token.ts";
import type { GeneralJsonWebSignature } from "../general.jsonwebsignature.ts";
import { deserialize } from "./deserialize.ts";

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, "", Symbol("a"), Buffer, Buffer.alloc(1), () => 1, []];

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

const invalidSignatures: any[] = [
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
  [undefined],
  [null],
  [true],
  [1],
  [1.2],
  [1n],
  ["a"],
  [Symbol("a")],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [[]],
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

describe("deserialize()", () => {
  const wrongSignatureToken: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
        signature: "oYyAwnx7D5WIo3L1WWx_zBSNX12nH8lwXQHgpPiApSk",
      },
    ],
  };

  // #region Unencoded Attached Token Without Dot
  const unencodedProtectedAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
        signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
      },
    ],
  };

  const missingUnencodedProtectedAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [{ protected: "eyJhbGciOiJIUzI1NiJ9", signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA" }],
  };

  const badUnencodedUnprotectedAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        header: { alg: "HS256", b64: false, crit: ["b64"], kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
      },
    ],
  };

  const missingUnencodedUnprotectedAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        header: { alg: "HS256", kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
      },
    ],
  };

  const unencodedFullAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
        signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
      },
    ],
  };

  const badUnencodedFullAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        header: { b64: false, crit: ["b64"], kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        protected: "eyJhbGciOiJIUzI1NiJ9",
        signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
      },
    ],
  };

  const missingUnencodedFullAttachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    payload: '{"iat": 1723010455, "sub": "078BWDDXasdcg8"}',
    signatures: [
      {
        header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        protected: "eyJhbGciOiJIUzI1NiJ9",
        signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
      },
    ],
  };
  // #endregion
  // #region Unencoded Detached Token Without Dot
  const unencodedProtectedDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
        signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
      },
    ],
  };

  const missingUnencodedProtectedDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [{ protected: "eyJhbGciOiJIUzI1NiJ9", signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA" }],
  };

  const badUnencodedUnprotectedDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { alg: "HS256", b64: false, crit: ["b64"], kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
      },
    ],
  };

  const missingUnencodedUnprotectedDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { alg: "HS256", kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
      },
    ],
  };

  const unencodedFullDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
        signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
      },
    ],
  };

  const badUnencodedFullDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { b64: false, crit: ["b64"], kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        protected: "eyJhbGciOiJIUzI1NiJ9",
        signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
      },
    ],
  };

  const missingUnencodedFullDetachedTokenWithoutDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        protected: "eyJhbGciOiJIUzI1NiJ9",
        signature: "uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA",
      },
    ],
  };
  // #endregion
  // #region Unencoded Detached Token With Dot
  const unencodedProtectedDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
        signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
      },
    ],
  };

  const missingUnencodedProtectedDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [{ protected: "eyJhbGciOiJIUzI1NiJ9", signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs" }],
  };

  const badUnencodedUnprotectedDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { alg: "HS256", b64: false, crit: ["b64"], kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
      },
    ],
  };

  const missingUnencodedUnprotectedDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { alg: "HS256", kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
      },
    ],
  };

  const unencodedFullDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        protected: "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19",
        signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
      },
    ],
  };

  const badUnencodedFullDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { b64: false, crit: ["b64"], kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        protected: "eyJhbGciOiJIUzI1NiJ9",
        signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
      },
    ],
  };

  const missingUnencodedFullDetachedTokenWithDot: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        protected: "eyJhbGciOiJIUzI1NiJ9",
        signature: "Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs",
      },
    ],
  };
  // #endregion
  // #region Encoded Attached Token
  const encodedProtectedAttachedToken: GeneralJsonWebSignatureToken = {
    payload: "eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0",
    signatures: [{ protected: "eyJhbGciOiJIUzI1NiJ9", signature: "hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA" }],
  };

  const encodedUnprotectedAttachedToken: GeneralJsonWebSignatureToken = {
    payload: "eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0",
    signatures: [
      {
        header: { alg: "HS256", kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        signature: "iRxcRLDYSMrd3ZlYZ_tUXP8pRAShmoErGTo4sEsew3U",
      },
    ],
  };

  const encodedFullAttachedToken: GeneralJsonWebSignatureToken = {
    payload: "eyJpYXQiOiAxNzIzMDEwNDU1LCAic3ViIjogIjA3OEJXRERYYXNkY2c4In0",
    signatures: [
      {
        header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        protected: "eyJhbGciOiJIUzI1NiJ9",
        signature: "hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA",
      },
    ],
  };
  // #endregion
  // #region Encoded Detached Token
  const encodedProtectedDetachedToken: GeneralJsonWebSignatureToken = {
    signatures: [{ protected: "eyJhbGciOiJIUzI1NiJ9", signature: "hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA" }],
  };

  const encodedUnprotectedDetachedToken: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { alg: "HS256", kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        signature: "iRxcRLDYSMrd3ZlYZ_tUXP8pRAShmoErGTo4sEsew3U",
      },
    ],
  };

  const encodedFullDetachedToken: GeneralJsonWebSignatureToken = {
    signatures: [
      {
        header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
        protected: "eyJhbGciOiJIUzI1NiJ9",
        signature: "hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA",
      },
    ],
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

  it.each(invalidTokens)(
    "should throw when the provided General JSON Web Signature Token is invalid.",
    async (token) => {
      const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
      await expect(deserialize(token)).rejects.toThrow(error);
    },
  );

  it.each(invalidDeserializeOptions)(
    "should throw when the provided General JSON Web Signature Deserialize Options is invalid.",
    async (options) => {
      const error = new TypeError("The provided General JSON Web Signature Deserialize Options is invalid.");
      await expect(deserialize(unencodedProtectedAttachedTokenWithoutDot, options)).rejects.toThrow(error);
    },
  );

  it.each(invalidDetachedPayloads)(
    'should throw when the provided General JSON Web Signature Deserialize Option "detachedPayload" is invalid.',
    async (detachedPayload) => {
      const error = new TypeError(
        'The provided General JSON Web Signature Deserialize Option "detachedPayload" is invalid.',
      );

      await expect(deserialize(unencodedProtectedAttachedTokenWithoutDot, { detachedPayload })).rejects.toThrow(error);
    },
  );

  it.each(invalidSignatures)(
    'should throw when the provided General JSON Web Signature Deserialize Option "signatures" is invalid.',
    async (signatures) => {
      const error = new TypeError(
        'The provided General JSON Web Signature Deserialize Option "signatures" is invalid.',
      );

      await expect(deserialize(unencodedProtectedAttachedTokenWithoutDot, { signatures })).rejects.toThrow(error);
    },
  );

  it.each(invalidJsonWebKeys)(
    'should throw when the provided General JSON Web Signature Deserialize Signature Option "jsonWebKey" is invalid.',
    async (_jsonWebKey) => {
      const error = new TypeError(
        'The provided General JSON Web Signature Deserialize Signature Option "jsonWebKey" is invalid.',
      );

      await expect(
        deserialize(unencodedProtectedAttachedTokenWithoutDot, { signatures: [{ jsonWebKey: _jsonWebKey }] }),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided General JSON Web Signature Deserialize Signature Option "expectedDigitalSignatureAlgorithms" is invalid.',
    async (expectedDigitalSignatureAlgorithms) => {
      const error = new TypeError(
        'The provided General JSON Web Signature Deserialize Signature Option "expectedDigitalSignatureAlgorithms" is invalid.',
      );

      await expect(
        deserialize(unencodedProtectedAttachedTokenWithoutDot, {
          signatures: [{ expectedDigitalSignatureAlgorithms }],
        }),
      ).rejects.toThrow(error);
    },
  );

  it('should throw when the General JSON Web Signature Deserialize Option "signatures" has length different than the signatures of the General JSON Web Signature Token.', async () => {
    const error = new TypeError(
      'The length of the General JSON Web Signature Deserialize Option "signatures" and the General JSON Web Signature Token Signatures do not match.',
    );

    await expect(
      deserialize(unencodedProtectedAttachedTokenWithoutDot, { signatures: [{ jsonWebKey }, { jsonWebKey }] }),
    ).rejects.toThrow(error);
  });

  it("should throw when deserializing a Detached General JSON Web Signature Token and not providing a Detached Payload.", async () => {
    const error = new InvalidJsonWebSignatureError("The JSON Web Signature requires a valid Payload.");
    await expect(deserialize(unencodedProtectedDetachedTokenWithoutDot)).rejects.toThrow(error);
  });

  it("should throw when providing a Detached Payload for a General JSON Web Signature Token that already has a Payload.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature already has a defined Payload.");

    await expect(
      deserialize(unencodedProtectedAttachedTokenWithoutDot, { detachedPayload: payloadWithoutDot }),
    ).rejects.toThrow(error);
  });

  it("should throw when the Digital Signature Algorithm of the General JSON Web Signature Token is unexpected.", async () => {
    const error = new InvalidJsonWebSignatureError('Unexpected Digital Signature Algorithm "HS256".');

    await expect(
      deserialize(unencodedProtectedAttachedTokenWithoutDot, {
        signatures: [{ expectedDigitalSignatureAlgorithms: ["HS512"] }],
      }),
    ).rejects.toThrow(error);
  });

  it("should throw when the provided Signature fails to deserialize the provided General JSON Web Signature Token.", async () => {
    const error = new InvalidJsonWebKeyError(
      "The provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
    );

    await expect(deserialize(wrongSignatureToken)).rejects.toThrow(error);
  });

  it("should return the deserialized General JSON Web Signature from an Unencoded Protected Attached Token without a dot.", async () => {
    await expect(
      deserialize(unencodedProtectedAttachedTokenWithoutDot, { signatures: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebSignature>({
      headers: [
        {
          header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
          protectedHeader: unencodedProtectedHeader,
          unprotectedHeader: null,
        },
      ],
      payload: payloadWithoutDot,
    });
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected Attached Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedProtectedAttachedTokenWithoutDot, { signatures: [{ jsonWebKey }] }),
    ).rejects.toThrow(error);
  });

  it("should throw when deserializing a General JSON Web Signature from an Unencoded Unprotected Attached Token without a dot.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(badUnencodedUnprotectedAttachedTokenWithoutDot, { signatures: [{ jsonWebKey }] }),
    ).rejects.toThrow(error);
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Unprotected Attached Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedUnprotectedAttachedTokenWithoutDot, { signatures: [{ jsonWebKey }] }),
    ).rejects.toThrow(error);
  });

  it("should return the deserialized General JSON Web Signature from an Unencoded Protected and Unprotected Attached Token without a dot.", async () => {
    await expect(
      deserialize(unencodedFullAttachedTokenWithoutDot, { signatures: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebSignature>({
      headers: [
        {
          header: new JsonWebSignatureHeader({
            ...unencodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          protectedHeader: unencodedProtectedHeader,
          unprotectedHeader,
        },
      ],
      payload: payloadWithoutDot,
    });
  });

  it("should throw when deserializing a General JSON Web Signature from an Unencoded Protected and Unprotected Attached Token without a dot.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(badUnencodedFullAttachedTokenWithoutDot, { signatures: [{ jsonWebKey }] }),
    ).rejects.toThrow(error);
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected and Unprotected Attached Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedFullAttachedTokenWithoutDot, { signatures: [{ jsonWebKey }] }),
    ).rejects.toThrow(error);
  });

  it("should return the deserialized General JSON Web Signature from an Unencoded Protected Detached Token without a dot.", async () => {
    await expect(
      deserialize(unencodedProtectedDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebSignature>({
      headers: [
        {
          header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
          protectedHeader: unencodedProtectedHeader,
          unprotectedHeader: null,
        },
      ],
      payload: payloadWithoutDot,
    });
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected Detached Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedProtectedDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrow(error);
  });

  it("should throw when deserializing a General JSON Web Signature from an Unencoded Unprotected Detached Token without a dot.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(badUnencodedUnprotectedDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrow(error);
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Unprotected Detached Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedUnprotectedDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrow(error);
  });

  it("should return the deserialized General JSON Web Signature from an Unencoded Protected and Unprotected Detached Token without a dot.", async () => {
    await expect(
      deserialize(unencodedFullDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebSignature>({
      headers: [
        {
          header: new JsonWebSignatureHeader({
            ...unencodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          protectedHeader: unencodedProtectedHeader,
          unprotectedHeader,
        },
      ],
      payload: payloadWithoutDot,
    });
  });

  it("should throw when deserializing a General JSON Web Signature from an Unencoded Protected and Unprotected Detached Token without a dot.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(badUnencodedFullDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrow(error);
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected and Unprotected Detached Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedFullDetachedTokenWithoutDot, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrow(error);
  });

  it("should return the deserialized General JSON Web Signature from an Unencoded Protected Detached Token with a dot.", async () => {
    await expect(
      deserialize(unencodedProtectedDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebSignature>({
      headers: [
        {
          header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
          protectedHeader: unencodedProtectedHeader,
          unprotectedHeader: null,
        },
      ],
      payload: payloadWithDot,
    });
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected Detached Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedProtectedDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrow(error);
  });

  it("should throw when deserializing a General JSON Web Signature from an Unencoded Unprotected Detached Token with a dot.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(badUnencodedUnprotectedDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrow(error);
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Unprotected Detached Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedUnprotectedDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrow(error);
  });

  it("should return the deserialized General JSON Web Signature from an Unencoded Protected and Unprotected Detached Token with a dot.", async () => {
    await expect(
      deserialize(unencodedFullDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebSignature>({
      headers: [
        {
          header: new JsonWebSignatureHeader({
            ...unencodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          protectedHeader: unencodedProtectedHeader,
          unprotectedHeader,
        },
      ],
      payload: payloadWithDot,
    });
  });

  it("should throw when deserializing a General JSON Web Signature from an Unencoded Protected and Unprotected Detached Token with a dot.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(badUnencodedFullDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrow(error);
  });

  it('should throw when deserializing a General JSON Web Signature from an Unencoded Protected and Unprotected Detached Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      deserialize(missingUnencodedFullDetachedTokenWithDot, {
        detachedPayload: payloadWithDot,
        signatures: [{ jsonWebKey }],
      }),
    ).rejects.toThrow(error);
  });

  it("should return the deserialized General JSON Web Signature from an Encoded Protected Attached Token without a dot.", async () => {
    await expect(
      deserialize(encodedProtectedAttachedToken, { signatures: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebSignature>({
      headers: [
        {
          header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
          protectedHeader: encodedProtectedHeader,
          unprotectedHeader: null,
        },
      ],
      payload: payloadWithoutDot,
    });
  });

  it("should return the deserialized General JSON Web Signature from an Encoded Unprotected Attached Token without a dot.", async () => {
    await expect(
      deserialize(encodedUnprotectedAttachedToken, { signatures: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebSignature>({
      headers: [
        {
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          protectedHeader: null,
          unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
        },
      ],
      payload: payloadWithoutDot,
    });
  });

  it("should return the deserialized General JSON Web Signature from an Encoded Protected and Unprotected Attached Token without a dot.", async () => {
    await expect(
      deserialize(encodedFullAttachedToken, { signatures: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebSignature>({
      headers: [
        {
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          protectedHeader: encodedProtectedHeader,
          unprotectedHeader,
        },
      ],
      payload: payloadWithoutDot,
    });
  });

  it("should return the deserialized General JSON Web Signature from an Encoded Protected Detached Token without a dot.", async () => {
    await expect(
      deserialize(encodedProtectedDetachedToken, { detachedPayload: payloadWithoutDot, signatures: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebSignature>({
      headers: [
        {
          header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
          protectedHeader: encodedProtectedHeader,
          unprotectedHeader: null,
        },
      ],
      payload: payloadWithoutDot,
    });
  });

  it("should return the deserialized General JSON Web Signature from an Encoded Unprotected Detached Token without a dot.", async () => {
    await expect(
      deserialize(encodedUnprotectedDetachedToken, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebSignature>({
      headers: [
        {
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          protectedHeader: null,
          unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
        },
      ],
      payload: payloadWithoutDot,
    });
  });

  it("should return the deserialized General JSON Web Signature from an Encoded Protected and Unprotected Detached Token without a dot.", async () => {
    await expect(
      deserialize(encodedFullDetachedToken, {
        detachedPayload: payloadWithoutDot,
        signatures: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebSignature>({
      headers: [
        {
          header: new JsonWebSignatureHeader({
            ...encodedProtectedHeader,
            ...unprotectedHeader,
          } as JsonWebSignatureHeaderParameters),
          protectedHeader: encodedProtectedHeader,
          unprotectedHeader,
        },
      ],
      payload: payloadWithoutDot,
    });
  });
});
