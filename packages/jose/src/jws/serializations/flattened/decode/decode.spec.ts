import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { describe, expect, it } from "vitest";

import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
import { JsonWebSignatureHeader } from "../../../header/jsonwebsignature.header.ts";
import type { FlattenedJsonWebSignatureParameters } from "../flattened.jsonwebsignature.parameters.ts";
import type { FlattenedJsonWebSignatureToken } from "../flattened.jsonwebsignature.token.ts";
import { decode } from "./decode.ts";

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol("a"), Buffer, Buffer.alloc(1), () => 1, []];

const invalidTokenFormats: any[] = [
  {},
  { protected: undefined },
  { protected: null },
  { protected: true },
  { protected: 1 },
  { protected: 1.2 },
  { protected: 1n },
  { protected: Symbol("a") },
  { protected: Buffer },
  { protected: Buffer.alloc(1) },
  { protected: () => 1 },
  { protected: {} },
  { protected: [] },
  { protected: "" },
  { header: undefined, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { header: null, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { header: true, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { header: 1, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { header: 1.2, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { header: 1n, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { header: "a", protected: "eyJhbGciOiJIUzI1NiJ9" },
  { header: Symbol("a"), protected: "eyJhbGciOiJIUzI1NiJ9" },
  { header: Buffer, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { header: Buffer.alloc(1), protected: "eyJhbGciOiJIUzI1NiJ9" },
  { header: () => 1, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { header: [], protected: "eyJhbGciOiJIUzI1NiJ9" },
  { payload: undefined, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { payload: null, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { payload: true, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { payload: 1, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { payload: 1.2, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { payload: 1n, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { payload: Symbol("a"), protected: "eyJhbGciOiJIUzI1NiJ9" },
  { payload: Buffer, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { payload: Buffer.alloc(1), protected: "eyJhbGciOiJIUzI1NiJ9" },
  { payload: () => 1, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { payload: {}, protected: "eyJhbGciOiJIUzI1NiJ9" },
  { payload: [], protected: "eyJhbGciOiJIUzI1NiJ9" },
  { payload: "", protected: "eyJhbGciOiJIUzI1NiJ9" },
  { protected: "eyJhbGciOiJIUzI1NiJ9", signature: undefined },
  { protected: "eyJhbGciOiJIUzI1NiJ9", signature: null },
  { protected: "eyJhbGciOiJIUzI1NiJ9", signature: true },
  { protected: "eyJhbGciOiJIUzI1NiJ9", signature: 1 },
  { protected: "eyJhbGciOiJIUzI1NiJ9", signature: 1.2 },
  { protected: "eyJhbGciOiJIUzI1NiJ9", signature: 1n },
  { protected: "eyJhbGciOiJIUzI1NiJ9", signature: Symbol("a") },
  { protected: "eyJhbGciOiJIUzI1NiJ9", signature: Buffer },
  { protected: "eyJhbGciOiJIUzI1NiJ9", signature: Buffer.alloc(1) },
  { protected: "eyJhbGciOiJIUzI1NiJ9", signature: () => 1 },
  { protected: "eyJhbGciOiJIUzI1NiJ9", signature: {} },
  { protected: "eyJhbGciOiJIUzI1NiJ9", signature: [] },
  { header: {}, protected: "ew", signature: "" },
  { header: {}, protected: "e30", signature: "" },
];

describe("decode()", () => {
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

  const unencodedSignatureWithoutDot = Buffer.from("uXQJV7FqjHNukDJPwTa4wtywtIoQ9CiBf16ETgFeKjA", "base64url");
  const unencodedSignatureWithDot = Buffer.from("Tb6KReuvHIM29TcHMTRZwMJAAs5zuCSX4gTMSplXjEs", "base64url");
  const encodedProtectedSignature = Buffer.from("hRqmKz7sKWQZyNM1Kw9AgqPNOedszPvEADYmNFo8foA", "base64url");
  const encodedUnprotectedSignature = Buffer.from("iRxcRLDYSMrd3ZlYZ_tUXP8pRAShmoErGTo4sEsew3U", "base64url");

  it.each(invalidTokens)(
    "should throw when the provided Flattened JSON Web Signature Token is invalid.",
    async (token) => {
      const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
      await expect(decode(token)).rejects.toThrow(error);
    },
  );

  it.each(invalidTokenFormats)(
    "should throw when the provided Flattened JSON Web Signature Token has an invalid format.",
    async (token) => {
      const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
      await expect(decode(token)).rejects.toThrow(error);
    },
  );

  it("should throw when there are repeated JSON Web Signature Header Parameters.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      decode({
        ...encodedProtectedAttachedToken,
        header: encodedProtectedHeader,
        protected: Buffer.from(JSON.stringify(encodedProtectedHeader), "utf8").toString("base64url"),
      }),
    ).rejects.toThrow(error);
  });

  it('should throw if the JOSE Header Parameter "crit" is present in the Unprotected Header.', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      decode({
        ...encodedProtectedAttachedToken,
        header: { crit: ["foo"], foo: "foo" },
        protected: Buffer.from(JSON.stringify({ alg: "HS256" }), "utf8").toString("base64url"),
      }),
    ).rejects.toThrow(error);
  });

  it('should throw if the JOSE Header Parameter "b64" is present in the Unprotected Header.', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    await expect(
      decode({
        ...encodedProtectedAttachedToken,
        header: { b64: false },
        protected: Buffer.from(JSON.stringify({ alg: "HS256" }), "utf8").toString("base64url"),
      }),
    ).rejects.toThrow(error);
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected Attached Unencoded Flattened JSON Web Signature Token without a dot.", async () => {
    await expect(
      decode(unencodedProtectedAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: unencodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader: null,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Attached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedProtectedAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: expect.not.stringContaining(payloadWithoutDot.toString("utf8")),
      protectedHeader: encodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader: null,
    });
  });

  it("should throw when providing an Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot.", async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    await expect(decode(badUnencodedUnprotectedAttachedTokenWithoutDot)).rejects.toThrow(error);
  });

  it('should return the Flattened JSON Web Signature Parameters from an Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedUnprotectedAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: expect.not.stringContaining(payloadWithoutDot.toString("utf8")),
      protectedHeader: null,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot.", async () => {
    await expect(
      decode(unencodedFullAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader({
        ...unencodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: unencodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader,
    });
  });

  it('should throw when providing a Protected and Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    await expect(decode(badUnencodedFullAttachedTokenWithoutDot)).rejects.toThrow(error);
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedFullAttachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: expect.not.stringContaining(payloadWithoutDot.toString("utf8")),
      protectedHeader: encodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader,
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected Detached Unencoded Flattened JSON Web Signature Token without a dot.", async () => {
    await expect(
      decode(unencodedProtectedDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: null,
      protectedHeader: unencodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader: null,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Detached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedProtectedDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: null,
      protectedHeader: encodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader: null,
    });
  });

  it('should throw when providing an Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    await expect(decode(badUnencodedUnprotectedDetachedTokenWithoutDot)).rejects.toThrow(error);
  });

  it('should return the Flattened JSON Web Signature Parameters from an Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedUnprotectedDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: null,
      protectedHeader: null,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot.", async () => {
    await expect(
      decode(unencodedFullDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader({
        ...unencodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: null,
      protectedHeader: unencodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader,
    });
  });

  it('should throw when providing a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    await expect(decode(badUnencodedFullDetachedTokenWithoutDot)).rejects.toThrow(error);
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedFullDetachedTokenWithoutDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: null,
      protectedHeader: encodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader,
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected Detached Unencoded Flattened JSON Web Signature Token with a dot.", async () => {
    await expect(
      decode(unencodedProtectedDetachedTokenWithDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader(unencodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: null,
      protectedHeader: unencodedProtectedHeader,
      signature: unencodedSignatureWithDot,
      unprotectedHeader: null,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Detached Unencoded Flattened JSON Web Signature Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedProtectedDetachedTokenWithDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: null,
      protectedHeader: encodedProtectedHeader,
      signature: unencodedSignatureWithDot,
      unprotectedHeader: null,
    });
  });

  it('should throw when providing an Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    await expect(decode(badUnencodedUnprotectedDetachedTokenWithDot)).rejects.toThrow(error);
  });

  it('should return the Flattened JSON Web Signature Parameters from an Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedUnprotectedDetachedTokenWithDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: null,
      protectedHeader: null,
      signature: unencodedSignatureWithDot,
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot.", async () => {
    await expect(decode(unencodedFullDetachedTokenWithDot)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>(
      {
        header: new JsonWebSignatureHeader({
          ...unencodedProtectedHeader,
          ...unprotectedHeader,
        } as JsonWebSignatureHeaderParameters),
        payload: null,
        protectedHeader: unencodedProtectedHeader,
        signature: unencodedSignatureWithDot,
        unprotectedHeader,
      },
    );
  });

  it('should throw when providing a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', async () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    await expect(decode(badUnencodedFullDetachedTokenWithDot)).rejects.toThrow(error);
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot that is missing the JOSE Header Parameter "b64".', async () => {
    await expect(
      decode(missingUnencodedFullDetachedTokenWithDot),
    ).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: null,
      protectedHeader: encodedProtectedHeader,
      signature: unencodedSignatureWithDot,
      unprotectedHeader,
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected Attached Encoded Flattened JSON Web Signature Token without a dot.", async () => {
    await expect(decode(encodedProtectedAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: encodedProtectedHeader,
      signature: encodedProtectedSignature,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from an Unprotected Attached Encoded Flattened JSON Web Signature Token without a dot.", async () => {
    await expect(decode(encodedUnprotectedAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: null,
      signature: encodedUnprotectedSignature,
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Attached Encoded Flattened JSON Web Signature Token without a dot.", async () => {
    await expect(decode(encodedFullAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: payloadWithoutDot,
      protectedHeader: encodedProtectedHeader,
      signature: encodedProtectedSignature,
      unprotectedHeader,
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected Detached Encoded Flattened JSON Web Signature Token without a dot.", async () => {
    await expect(decode(encodedProtectedDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader(encodedProtectedHeader as JsonWebSignatureHeaderParameters),
      payload: null,
      protectedHeader: encodedProtectedHeader,
      signature: encodedProtectedSignature,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from an Unprotected Detached Encoded Flattened JSON Web Signature Token without a dot.", async () => {
    await expect(decode(encodedUnprotectedDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: null,
      protectedHeader: null,
      signature: encodedUnprotectedSignature,
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Encoded Flattened JSON Web Signature Token without a dot.", async () => {
    await expect(decode(encodedFullDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebSignatureParameters>({
      header: new JsonWebSignatureHeader({
        ...encodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters),
      payload: null,
      protectedHeader: encodedProtectedHeader,
      signature: encodedProtectedSignature,
      unprotectedHeader,
    });
  });
});
