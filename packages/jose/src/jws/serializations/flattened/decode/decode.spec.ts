import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { describe, expect, it } from "vitest";

import { InvalidJsonWebSignatureError } from "../../../../errors/invalid-jsonwebsignature.error.ts";
import type { JsonWebSignatureHeaderParameters } from "../../../header/jsonwebsignature.header.parameters.ts";
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

  it.each(invalidTokens)("should throw when the provided Flattened JSON Web Signature Token is invalid.", (token) => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    expect(() => decode(token)).toThrow(error);
  });

  it.each(invalidTokenFormats)(
    "should throw when the provided Flattened JSON Web Signature Token has an invalid format.",
    (token) => {
      const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
      expect(() => decode(token)).toThrow(error);
    },
  );

  it("should throw when there are repeated JSON Web Signature Header Parameters.", () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    expect(() =>
      decode({
        ...encodedProtectedAttachedToken,
        header: encodedProtectedHeader,
        protected: Buffer.from(JSON.stringify(encodedProtectedHeader), "utf8").toString("base64url"),
      }),
    ).toThrow(error);
  });

  it('should throw if the JOSE Header Parameter "crit" is present in the Unprotected Header.', () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    expect(() =>
      decode({
        ...encodedProtectedAttachedToken,
        header: { crit: ["foo"], foo: "foo" },
        protected: Buffer.from(JSON.stringify({ alg: "HS256" }), "utf8").toString("base64url"),
      }),
    ).toThrow(error);
  });

  it('should throw if the JOSE Header Parameter "b64" is present in the Unprotected Header.', () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");

    expect(() =>
      decode({
        ...encodedProtectedAttachedToken,
        header: { b64: false },
        protected: Buffer.from(JSON.stringify({ alg: "HS256" }), "utf8").toString("base64url"),
      }),
    ).toThrow(error);
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected Attached Unencoded Flattened JSON Web Signature Token without a dot.", () => {
    expect(decode(unencodedProtectedAttachedTokenWithoutDot)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: unencodedProtectedHeader as JsonWebSignatureHeaderParameters,
      payload: payloadWithoutDot,
      protectedHeader: unencodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader: null,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Attached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', () => {
    expect(decode(missingUnencodedProtectedAttachedTokenWithoutDot)).toStrictEqual<FlattenedJsonWebSignatureParameters>(
      {
        joseHeader: encodedProtectedHeader as JsonWebSignatureHeaderParameters,
        payload: expect.not.stringContaining(payloadWithoutDot.toString("utf8")),
        protectedHeader: encodedProtectedHeader,
        signature: unencodedSignatureWithoutDot,
        unprotectedHeader: null,
      },
    );
  });

  it("should throw when providing an Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot.", () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    expect(() => decode(badUnencodedUnprotectedAttachedTokenWithoutDot)).toThrow(error);
  });

  it('should return the Flattened JSON Web Signature Parameters from an Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', () => {
    expect(
      decode(missingUnencodedUnprotectedAttachedTokenWithoutDot),
    ).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: { ...encodedProtectedHeader, ...unprotectedHeader } as JsonWebSignatureHeaderParameters,
      payload: expect.not.stringContaining(payloadWithoutDot.toString("utf8")),
      protectedHeader: null,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot.", () => {
    expect(decode(unencodedFullAttachedTokenWithoutDot)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: { ...unencodedProtectedHeader, ...unprotectedHeader } as JsonWebSignatureHeaderParameters,
      payload: payloadWithoutDot,
      protectedHeader: unencodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader,
    });
  });

  it('should throw when providing a Protected and Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    expect(() => decode(badUnencodedFullAttachedTokenWithoutDot)).toThrow(error);
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Attached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', () => {
    expect(decode(missingUnencodedFullAttachedTokenWithoutDot)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: { ...encodedProtectedHeader, ...unprotectedHeader } as JsonWebSignatureHeaderParameters,
      payload: expect.not.stringContaining(payloadWithoutDot.toString("utf8")),
      protectedHeader: encodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader,
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected Detached Unencoded Flattened JSON Web Signature Token without a dot.", () => {
    expect(decode(unencodedProtectedDetachedTokenWithoutDot)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: unencodedProtectedHeader as JsonWebSignatureHeaderParameters,
      payload: null,
      protectedHeader: unencodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader: null,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Detached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', () => {
    expect(decode(missingUnencodedProtectedDetachedTokenWithoutDot)).toStrictEqual<FlattenedJsonWebSignatureParameters>(
      {
        joseHeader: encodedProtectedHeader as JsonWebSignatureHeaderParameters,
        payload: null,
        protectedHeader: encodedProtectedHeader,
        signature: unencodedSignatureWithoutDot,
        unprotectedHeader: null,
      },
    );
  });

  it('should throw when providing an Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    expect(() => decode(badUnencodedUnprotectedDetachedTokenWithoutDot)).toThrow(error);
  });

  it('should return the Flattened JSON Web Signature Parameters from an Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', () => {
    expect(
      decode(missingUnencodedUnprotectedDetachedTokenWithoutDot),
    ).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: { ...encodedProtectedHeader, ...unprotectedHeader } as JsonWebSignatureHeaderParameters,
      payload: null,
      protectedHeader: null,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot.", () => {
    expect(decode(unencodedFullDetachedTokenWithoutDot)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: { ...unencodedProtectedHeader, ...unprotectedHeader } as JsonWebSignatureHeaderParameters,
      payload: null,
      protectedHeader: unencodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader,
    });
  });

  it('should throw when providing a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    expect(() => decode(badUnencodedFullDetachedTokenWithoutDot)).toThrow(error);
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token without a dot that is missing the JOSE Header Parameter "b64".', () => {
    expect(decode(missingUnencodedFullDetachedTokenWithoutDot)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: { ...encodedProtectedHeader, ...unprotectedHeader } as JsonWebSignatureHeaderParameters,
      payload: null,
      protectedHeader: encodedProtectedHeader,
      signature: unencodedSignatureWithoutDot,
      unprotectedHeader,
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected Detached Unencoded Flattened JSON Web Signature Token with a dot.", () => {
    expect(decode(unencodedProtectedDetachedTokenWithDot)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: unencodedProtectedHeader as JsonWebSignatureHeaderParameters,
      payload: null,
      protectedHeader: unencodedProtectedHeader,
      signature: unencodedSignatureWithDot,
      unprotectedHeader: null,
    });
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected Detached Unencoded Flattened JSON Web Signature Token with a dot that is missing the JOSE Header Parameter "b64".', () => {
    expect(decode(missingUnencodedProtectedDetachedTokenWithDot)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: encodedProtectedHeader as JsonWebSignatureHeaderParameters,
      payload: null,
      protectedHeader: encodedProtectedHeader,
      signature: unencodedSignatureWithDot,
      unprotectedHeader: null,
    });
  });

  it('should throw when providing an Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    expect(() => decode(badUnencodedUnprotectedDetachedTokenWithDot)).toThrow(error);
  });

  it('should return the Flattened JSON Web Signature Parameters from an Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot that is missing the JOSE Header Parameter "b64".', () => {
    expect(decode(missingUnencodedUnprotectedDetachedTokenWithDot)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: { ...encodedProtectedHeader, ...unprotectedHeader } as JsonWebSignatureHeaderParameters,
      payload: null,
      protectedHeader: null,
      signature: unencodedSignatureWithDot,
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot.", () => {
    expect(decode(unencodedFullDetachedTokenWithDot)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: {
        ...unencodedProtectedHeader,
        ...unprotectedHeader,
      } as JsonWebSignatureHeaderParameters,
      payload: null,
      protectedHeader: unencodedProtectedHeader,
      signature: unencodedSignatureWithDot,
      unprotectedHeader,
    });
  });

  it('should throw when providing a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot where the JOSE Header Parameter "b64" is in the Unprotected Header.', () => {
    const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
    expect(() => decode(badUnencodedFullDetachedTokenWithDot)).toThrow(error);
  });

  it('should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Unencoded Flattened JSON Web Signature Token with a dot that is missing the JOSE Header Parameter "b64".', () => {
    expect(decode(missingUnencodedFullDetachedTokenWithDot)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: { ...encodedProtectedHeader, ...unprotectedHeader } as JsonWebSignatureHeaderParameters,
      payload: null,
      protectedHeader: encodedProtectedHeader,
      signature: unencodedSignatureWithDot,
      unprotectedHeader,
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected Attached Encoded Flattened JSON Web Signature Token without a dot.", () => {
    expect(decode(encodedProtectedAttachedToken)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: encodedProtectedHeader as JsonWebSignatureHeaderParameters,
      payload: payloadWithoutDot,
      protectedHeader: encodedProtectedHeader,
      signature: encodedProtectedSignature,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from an Unprotected Attached Encoded Flattened JSON Web Signature Token without a dot.", () => {
    expect(decode(encodedUnprotectedAttachedToken)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: { ...encodedProtectedHeader, ...unprotectedHeader } as JsonWebSignatureHeaderParameters,
      payload: payloadWithoutDot,
      protectedHeader: null,
      signature: encodedUnprotectedSignature,
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Attached Encoded Flattened JSON Web Signature Token without a dot.", () => {
    expect(decode(encodedFullAttachedToken)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: { ...encodedProtectedHeader, ...unprotectedHeader } as JsonWebSignatureHeaderParameters,
      payload: payloadWithoutDot,
      protectedHeader: encodedProtectedHeader,
      signature: encodedProtectedSignature,
      unprotectedHeader,
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected Detached Encoded Flattened JSON Web Signature Token without a dot.", () => {
    expect(decode(encodedProtectedDetachedToken)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: encodedProtectedHeader as JsonWebSignatureHeaderParameters,
      payload: null,
      protectedHeader: encodedProtectedHeader,
      signature: encodedProtectedSignature,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from an Unprotected Detached Encoded Flattened JSON Web Signature Token without a dot.", () => {
    expect(decode(encodedUnprotectedDetachedToken)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: { ...encodedProtectedHeader, ...unprotectedHeader } as JsonWebSignatureHeaderParameters,
      payload: null,
      protectedHeader: null,
      signature: encodedUnprotectedSignature,
      unprotectedHeader: { ...encodedProtectedHeader, ...unprotectedHeader },
    });
  });

  it("should return the Flattened JSON Web Signature Parameters from a Protected and Unprotected Detached Encoded Flattened JSON Web Signature Token without a dot.", () => {
    expect(decode(encodedFullDetachedToken)).toStrictEqual<FlattenedJsonWebSignatureParameters>({
      joseHeader: { ...encodedProtectedHeader, ...unprotectedHeader } as JsonWebSignatureHeaderParameters,
      payload: null,
      protectedHeader: encodedProtectedHeader,
      signature: encodedProtectedSignature,
      unprotectedHeader,
    });
  });
});
