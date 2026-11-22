import { Buffer } from "node:buffer";
import { KeyObject } from "node:crypto";
import type { KeyObjectType } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import { KeyTypeBackend } from "../key-type.backend.ts";
import type { OctetSequenceJsonWebKeyParameters } from "./octet-sequence.jsonwebkey.parameters.ts";
import { OctetSequenceKeyTypeBackend } from "./octet-sequence.key-type.backend.ts";

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

describe("Octet Sequence Key Type Backend", () => {
  const backend = new OctetSequenceKeyTypeBackend();

  const parameters: OctetSequenceJsonWebKeyParameters = {
    k: "qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ",
    kty: "oct",
  };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("name", () => {
    it('should have "oct" as its value.', () => {
      expect(backend.name).toBe<OctetSequenceJsonWebKeyParameters["kty"]>("oct");
    });
  });

  describe("generate()", () => {
    it.each(invalidGenerateOptions)(
      "should throw when the provided Octet Sequence JSON Web Key Generation Options is invalid.",
      async (options) => {
        const error = new TypeError("The provided Octet Sequence JSON Web Key Generation Options is invalid.");
        await expect(backend.generate(options)).rejects.toThrow(error);
      },
    );

    it.each(invalidLengthGenerateOptions)(
      'should throw when the provided Octet Sequence JSON Web Key Generation Option "length" is invalid.',
      async (length) => {
        const error = new TypeError('The provided Octet Sequence JSON Web Key Generation Option "length" is invalid.');
        await expect(backend.generate({ length })).rejects.toThrow(error);
      },
    );

    it("should return the generated Octet Sequence JSON Web Key.", async () => {
      let jsonWebKey!: JsonWebKey<OctetSequenceJsonWebKeyParameters>;

      await expect(
        (async () => {
          jsonWebKey = await backend.generate({ length: 256 });
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
          jsonWebKey = await backend.generate({ length: 256 }, { alg: "HS256", kid: "r7DSGf2hS0g8o4Zn", kty: "RSA" });
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

      expect(() => (cryptoKey = backend.getCryptoKey(parameters))).not.toThrow();

      expect(cryptoKey).toBeInstanceOf(KeyObject);
      expect(cryptoKey.type).toBe<KeyObjectType>("secret");
      expect(cryptoKey.export({ format: "jwk" })).toStrictEqual(parameters);
    });
  });

  describe("getPrivateParameters()", () => {
    it("should return [].", () => {
      expect(backend.getPrivateParameters()).toStrictEqual<string[]>([]);
    });
  });

  describe("validate()", () => {
    let superValidateSpy: Mock<(parameters: any) => void>;

    beforeEach(() => {
      superValidateSpy = vi.spyOn(KeyTypeBackend.prototype, "validate");
    });

    it.each(invalidKs)('should throw when the provided JSON Web Key Parameter "k" is invalid.', (k) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "k".');

      expect(() => backend.validate({ ...parameters, k })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it("should not throw when the provided JSON Web Key Parameters is valid.", () => {
      expect(() => backend.validate(parameters)).not.toThrow();
      expect(superValidateSpy).toHaveBeenCalledExactlyOnceWith(parameters);
    });
  });
});
