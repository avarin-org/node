import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJsonWebKeySetError } from "../../errors/invalid-jsonwebkeyset.error.ts";
import type { EllipticCurveJsonWebKeyParameters } from "../../jwa/jwk/ec/elliptic-curve.jsonwebkey.parameters.ts";
import type { RsaJsonWebKeyParameters } from "../../jwa/jwk/rsa/rsa.jsonwebkey.parameters.ts";
import { jwk } from "../../jwk/index.ts";
import type { JsonWebKeyParameters } from "../../jwk/jsonwebkey.parameters.ts";
import { JsonWebKey } from "../../jwk/jsonwebkey.ts";
import type { JsonWebKeySetParameters } from "../jsonwebkeyset.parameters.ts";
import type { JsonWebKeySet } from "../jsonwebkeyset.ts";
import { create } from "./create.ts";

const invalidKeys: any[] = [
  [[]],
  [[undefined]],
  [[null]],
  [[true]],
  [[1]],
  [[1.2]],
  [[1n]],
  [["a"]],
  [[Symbol("a")]],
  [[Buffer]],
  [[Buffer.alloc(1)]],
  [[() => 1]],
  [[{}]],
  [[[]]],
];

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
];

const invalidJsonWebKeySetParameters: any[] = [
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
  [{}],
  [{ kty: undefined }],
  [{ kty: null }],
  [{ kty: true }],
  [{ kty: 1 }],
  [{ kty: 1.2 }],
  [{ kty: 1n }],
  [{ kty: "a" }],
  [{ kty: Symbol("a") }],
  [{ kty: Buffer }],
  [{ kty: Buffer.alloc(1) }],
  [{ kty: () => 1 }],
  [{ kty: {} }],
  [{ kty: [] }],
];

const publicEllipticCurveParameters: EllipticCurveJsonWebKeyParameters = {
  crv: "P-256",
  kty: "EC",
  x: "4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og",
  y: "mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8",
};

const publicRsaParameters: RsaJsonWebKeyParameters = {
  e: "AQAB",
  kty: "RSA",
  n:
    "xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB" +
    "yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S" +
    "n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK" +
    "FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR" +
    "QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S" +
    "5JG5iK0nsm1uZYu-02XN-w",
};

const duplicateKeyIdentifiers: JsonWebKey[] = [
  new JsonWebKey({ ...publicEllipticCurveParameters, kid: "key-id" }),
  new JsonWebKey({ ...publicRsaParameters, kid: "key-id" }),
];

describe("create()", () => {
  describe("constructor", () => {
    it.each(invalidKeys)("should throw when the provided JSON Web Keys is invalid.", async (keys) => {
      const error = new InvalidJsonWebKeySetError("The provided JSON Web Keys is invalid.");
      await expect(create(keys)).rejects.toThrow(error);
    });

    it("should throw when the provided JSON Web Keys have duplicate Keys or Identifiers.", async () => {
      const error = new InvalidJsonWebKeySetError("The use of duplicate JSON Web Keys is forbidden.");
      await expect(create(duplicateKeyIdentifiers)).rejects.toThrow(error);
    });

    it.each(invalidParameters)(
      "should throw when the provided JSON Web Key Set Parameters is invalid.",
      async (parameters) => {
        const error = new InvalidJsonWebKeySetError("The provided JSON Web Key Set Parameters is invalid.");
        await expect(create(parameters)).rejects.toThrow(error);
      },
    );

    it.each(invalidJsonWebKeySetParameters)(
      'should throw when the provided JSON Web Key Set Parameter "keys" is invalid.',
      async (keys) => {
        const error = new InvalidJsonWebKeySetError('Invalid JSON Web Key Set Parameter "keys".');
        await expect(create({ keys })).rejects.toThrow(error);
      },
    );

    it("should throw when the provided JSON Web Key Set have duplicate Keys or Identifiers.", async () => {
      const error = new InvalidJsonWebKeySetError('Invalid JSON Web Key Set Parameter "keys".');
      await expect(create({ keys: duplicateKeyIdentifiers.map((key) => key.parameters) })).rejects.toThrow(error);
    });

    it("should return a JSON Web Key Set from the provided JSON Web Keys.", async () => {
      let jsonWebKeySet!: JsonWebKeySet;

      const keys: JsonWebKey[] = [
        await jwk.create(publicEllipticCurveParameters, { kid: "ec-key" }),
        await jwk.create(publicRsaParameters, { kid: "rsa-key" }),
      ];

      await expect(
        (async () => {
          jsonWebKeySet = await create(keys);
        })(),
      ).resolves.not.toThrow();

      expect(jsonWebKeySet.keys).toHaveLength(2);

      jsonWebKeySet.keys.forEach((jsonWebKey, i) => {
        expect(jsonWebKey).toBeInstanceOf(JsonWebKey);
        expect(jsonWebKey.parameters).toStrictEqual<JsonWebKeyParameters>(keys[i]!.parameters);
      });
    });

    it("should return a JSON Web Key Set from the provided JSON Web Key Set Parameters.", async () => {
      let jsonWebKeySet!: JsonWebKeySet;

      const parameters: JsonWebKeySetParameters = {
        keys: [
          { ...publicEllipticCurveParameters, kid: "ec-key" },
          { ...publicRsaParameters, kid: "rsa-key" },
        ],
      };

      await expect(
        (async () => {
          jsonWebKeySet = await create(parameters);
        })(),
      ).resolves.not.toThrow();

      expect(jsonWebKeySet.keys).toHaveLength(2);

      jsonWebKeySet.keys.forEach((jsonWebKey, i) => {
        expect(jsonWebKey).toBeInstanceOf(JsonWebKey);
        expect(jsonWebKey.parameters).toStrictEqual<JsonWebKeyParameters>(parameters.keys[i]!);
      });
    });
  });
});
