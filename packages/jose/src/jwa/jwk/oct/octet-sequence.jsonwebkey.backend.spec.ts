import { Buffer } from "node:buffer";
import { KeyObject } from "node:crypto";
import type { KeyObjectType } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import { JsonWebKeyBackend } from "../jsonwebkey.backend.ts";
import { OctetSequenceJsonWebKeyBackend } from "./octet-sequence.jsonwebkey.backend.ts";
import type { OctetSequenceJsonWebKeyParameters } from "./octet-sequence.jsonwebkey.parameters.ts";

const invalidGenerateOptions: any[] = [
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

const invalidLengthGenerateOptions: any[] = [
  undefined,
  null,
  true,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  -1,
];

const invalidKs: any[] = [
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
  "=",
];

describe("Octet Sequence JSON Web Key Backend", () => {
  const parameters: OctetSequenceJsonWebKeyParameters = {
    k: "qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ",
    kty: "oct",
  };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("keyType", () => {
    it('should have "oct" as its value.', () => {
      expect(OctetSequenceJsonWebKeyBackend.keyType).toBe<OctetSequenceJsonWebKeyParameters["kty"]>("oct");
    });
  });

  describe("constructor", () => {
    let superValidateSpy: Mock<(parameters: any) => void>;

    beforeEach(() => {
      superValidateSpy = vi.spyOn(JsonWebKeyBackend.prototype, "validate");
    });

    it.each(invalidKs)('should throw when the provided JSON Web Key Parameter "k" is invalid.', (k) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "k".');

      expect(() => new OctetSequenceJsonWebKeyBackend({ ...parameters, k })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it("should return an instance of an Octet Sequence JSON Web Key Backend.", () => {
      let backend!: OctetSequenceJsonWebKeyBackend;

      expect(() => (backend = new OctetSequenceJsonWebKeyBackend(parameters))).not.toThrow();

      expect(backend).toBeInstanceOf(OctetSequenceJsonWebKeyBackend);
      expect(backend.parameters).toStrictEqual(parameters);

      expect(superValidateSpy).toHaveBeenCalledExactlyOnceWith(parameters);
    });
  });

  describe("generate()", () => {
    it.each(invalidGenerateOptions)(
      "should throw when the provided Octet Sequence JSON Web Key Generation Options is invalid.",
      async (options) => {
        const error = new TypeError("The provided Octet Sequence JSON Web Key Generation Options is invalid.");
        await expect(OctetSequenceJsonWebKeyBackend.generate(options)).rejects.toThrow(error);
      },
    );

    it.each(invalidLengthGenerateOptions)(
      'should throw when the provided Octet Sequence JSON Web Key Generation Option "length" is invalid.',
      async (length) => {
        const error = new TypeError('The provided Octet Sequence JSON Web Key Generation Option "length" is invalid.');
        await expect(OctetSequenceJsonWebKeyBackend.generate({ length })).rejects.toThrow(error);
      },
    );

    it("should return the generated Octet Sequence JSON Web Key.", async () => {
      let jsonWebKey!: JsonWebKey<OctetSequenceJsonWebKeyParameters>;

      await expect(
        (async () => {
          jsonWebKey = await OctetSequenceJsonWebKeyBackend.generate({ length: 256 });
        })(),
      ).resolves.not.toThrow();

      expect(jsonWebKey).toBeInstanceOf(JsonWebKey);
      expect(jsonWebKey.toJSON(true)).toStrictEqual<OctetSequenceJsonWebKeyParameters>({
        k: expect.any(String),
        kty: "oct",
      });
    });

    it("should return the generated Octet Sequence JSON Web Key with the provided additional JSON Web Key Parameters.", async () => {
      let jsonWebKey!: JsonWebKey<OctetSequenceJsonWebKeyParameters>;

      await expect(
        (async () => {
          jsonWebKey = await OctetSequenceJsonWebKeyBackend.generate(
            { length: 256 },
            { alg: "HS256", kid: "r7DSGf2hS0g8o4Zn", kty: "RSA" },
          );
        })(),
      ).resolves.not.toThrow();

      expect(jsonWebKey).toBeInstanceOf(JsonWebKey);
      expect(jsonWebKey.toJSON(true)).toStrictEqual<OctetSequenceJsonWebKeyParameters>({
        alg: "HS256",
        k: expect.any(String),
        kid: "r7DSGf2hS0g8o4Zn",
        kty: "oct",
      });
    });
  });

  describe("getCryptoKey()", () => {
    it("should return a Secret Native Crypto Key.", () => {
      let cryptoKey!: KeyObject;
      const backend = new OctetSequenceJsonWebKeyBackend(parameters);

      expect(() => (cryptoKey = backend.getCryptoKey())).not.toThrow();

      expect(cryptoKey).toBeInstanceOf(KeyObject);
      expect(cryptoKey.type).toBe<KeyObjectType>("secret");
      expect(cryptoKey.export({ format: "jwk" })).toStrictEqual(parameters);
    });
  });

  describe("toJSON()", () => {
    const jsonWebKeyBackend = new OctetSequenceJsonWebKeyBackend(parameters);

    it("should return the JSON Web Key Parameters of the Key when exportPrivate is undefined.", () => {
      expect(jsonWebKeyBackend.toJSON()).toStrictEqual(parameters);
      expect(jsonWebKeyBackend.parameters).toStrictEqual(parameters);
    });

    it("should return the JSON Web Key Parameters of the Key when exportPrivate is false.", () => {
      expect(jsonWebKeyBackend.toJSON(false)).toStrictEqual(parameters);
      expect(jsonWebKeyBackend.parameters).toStrictEqual(parameters);
    });

    it("should return the JSON Web Key Parameters of the Key when exportPrivate is true.", () => {
      expect(jsonWebKeyBackend.toJSON(true)).toStrictEqual(parameters);
      expect(jsonWebKeyBackend.parameters).toStrictEqual(parameters);
    });
  });
});
