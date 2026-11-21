import { Buffer } from "node:buffer";
import { KeyObject } from "node:crypto";
import type { KeyObjectType } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import { JsonWebKeyBackend } from "../jsonwebkey.backend.ts";
import { EllipticCurveJsonWebKeyBackend } from "./elliptic-curve.jsonwebkey.backend.ts";
import type { EllipticCurveJsonWebKeyParameters } from "./elliptic-curve.jsonwebkey.parameters.ts";

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

const invalidCrvs: any[] = [
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
  "a",
];

const invalidXs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol("a"), Buffer, Buffer.alloc(1), () => 1, {}, [], ""];
const invalidYs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol("a"), Buffer, Buffer.alloc(1), () => 1, {}, [], ""];
const invalidDs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol("a"), Buffer, Buffer.alloc(1), () => 1, {}, [], ""];

describe("Elliptic Curve JSON Web Key Backend", () => {
  const publicParameters: EllipticCurveJsonWebKeyParameters = {
    crv: "P-256",
    kty: "EC",
    x: "4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og",
    y: "mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8",
  };

  const privateParameters: EllipticCurveJsonWebKeyParameters = {
    ...publicParameters,
    d: "bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo",
  };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("keyType", () => {
    it('should have "EC" as its value.', () => {
      expect(EllipticCurveJsonWebKeyBackend.keyType).toBe<EllipticCurveJsonWebKeyParameters["kty"]>("EC");
    });
  });

  describe("constructor", () => {
    let superValidateSpy: Mock<(parameters: any) => void>;

    beforeEach(() => {
      superValidateSpy = vi.spyOn(JsonWebKeyBackend.prototype, "validate");
    });

    it.each(invalidCrvs)('should throw when the provided JSON Web Key Parameter "crv" is invalid.', (crv) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "crv".');

      expect(() => new EllipticCurveJsonWebKeyBackend({ ...publicParameters, crv })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it.each(invalidXs)('should throw when the provided JSON Web Key Parameter "x" is invalid.', (x) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "x".');

      expect(() => new EllipticCurveJsonWebKeyBackend({ ...publicParameters, x })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it.each(invalidYs)('should throw when the provided JSON Web Key Parameter "y" is invalid.', (y) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "y".');

      expect(() => new EllipticCurveJsonWebKeyBackend({ ...publicParameters, y })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it.each(invalidDs)('should throw when the provided JSON Web Key Parameter "d" is invalid.', (d) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "d".');

      expect(() => new EllipticCurveJsonWebKeyBackend({ ...publicParameters, d })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it.each([publicParameters, privateParameters])(
      "should return an instance of an Elliptic Curve JSON Web Key Backend.",
      (parameters) => {
        let backend!: EllipticCurveJsonWebKeyBackend;

        expect(() => (backend = new EllipticCurveJsonWebKeyBackend(parameters))).not.toThrow();

        expect(backend).toBeInstanceOf(EllipticCurveJsonWebKeyBackend);
        expect(backend.parameters).toStrictEqual(parameters);

        expect(superValidateSpy).toHaveBeenCalledExactlyOnceWith(parameters);
      },
    );
  });

  describe("generate()", () => {
    it.each(invalidGenerateOptions)(
      "should throw when the provided Elliptic Curve JSON Web Key Generation Options is invalid.",
      async (options) => {
        const error = new TypeError("The provided Elliptic Curve JSON Web Key Generation Options is invalid.");
        await expect(EllipticCurveJsonWebKeyBackend.generate(options)).rejects.toThrow(error);
      },
    );

    it.each(invalidCrvs)(
      'should throw when the provided Elliptic Curve JSON Web Key Generation Option "curve" is invalid.',
      async (curve) => {
        const error = new TypeError('The provided Elliptic Curve JSON Web Key Generation Option "curve" is invalid.');
        await expect(EllipticCurveJsonWebKeyBackend.generate({ curve })).rejects.toThrow(error);
      },
    );

    it("should return the generated Private Elliptic Curve JSON Web Key.", async () => {
      let jsonWebKey!: JsonWebKey<EllipticCurveJsonWebKeyParameters>;

      await expect(
        (async () => {
          jsonWebKey = await EllipticCurveJsonWebKeyBackend.generate({ curve: "P-256" });
        })(),
      ).resolves.not.toThrow();

      expect(jsonWebKey).toBeInstanceOf(JsonWebKey);
      expect(jsonWebKey.toJSON(true)).toStrictEqual<EllipticCurveJsonWebKeyParameters>({
        crv: "P-256",
        d: expect.any(String),
        kty: "EC",
        x: expect.any(String),
        y: expect.any(String),
      });
    });

    it("should return the generated Private Elliptic Curve JSON Web Key with the provided additional JSON Web Key Parameters.", async () => {
      let jsonWebKey!: JsonWebKey<EllipticCurveJsonWebKeyParameters>;

      await expect(
        (async () => {
          jsonWebKey = await EllipticCurveJsonWebKeyBackend.generate(
            { curve: "P-256" },
            { alg: "ES256", kid: "kmg2kzFpBL3r4nVC", kty: "oct" },
          );
        })(),
      ).resolves.not.toThrow();

      expect(jsonWebKey).toBeInstanceOf(JsonWebKey);
      expect(jsonWebKey.toJSON(true)).toStrictEqual<EllipticCurveJsonWebKeyParameters>({
        alg: "ES256",
        crv: "P-256",
        d: expect.any(String),
        kid: "kmg2kzFpBL3r4nVC",
        kty: "EC",
        x: expect.any(String),
        y: expect.any(String),
      });
    });
  });

  describe("getCryptoKey()", () => {
    it("should return a Public Native Crypto Key.", () => {
      let cryptoKey!: KeyObject;
      const backend = new EllipticCurveJsonWebKeyBackend(publicParameters);

      expect(() => (cryptoKey = backend.getCryptoKey())).not.toThrow();

      expect(cryptoKey).toBeInstanceOf(KeyObject);
      expect(cryptoKey.type).toBe<KeyObjectType>("public");
      expect(cryptoKey.export({ format: "jwk" })).toStrictEqual(publicParameters);
    });

    it("should return a Private Native Crypto Key.", () => {
      let cryptoKey!: KeyObject;
      const backend = new EllipticCurveJsonWebKeyBackend(privateParameters);

      expect(() => (cryptoKey = backend.getCryptoKey())).not.toThrow();

      expect(cryptoKey).toBeInstanceOf(KeyObject);
      expect(cryptoKey.type).toBe<KeyObjectType>("private");
      expect(cryptoKey.export({ format: "jwk" })).toStrictEqual(privateParameters);
    });
  });

  describe("toJSON()", () => {
    const publicJsonWebKeyBackend = new EllipticCurveJsonWebKeyBackend(publicParameters);
    const privateJsonWebKeyBackend = new EllipticCurveJsonWebKeyBackend(privateParameters);

    it("should return the Public JSON Web Key Parameters of the Public Key when exportPrivate is undefined.", () => {
      expect(publicJsonWebKeyBackend.toJSON()).toStrictEqual(publicParameters);
      expect(publicJsonWebKeyBackend.parameters).toStrictEqual(publicParameters);
    });

    it("should return the Public JSON Web Key Parameters of the Public Key when exportPrivate is false.", () => {
      expect(publicJsonWebKeyBackend.toJSON(false)).toStrictEqual(publicParameters);
      expect(publicJsonWebKeyBackend.parameters).toStrictEqual(publicParameters);
    });

    it("should return the Public JSON Web Key Parameters of the Public Key when exportPrivate is true.", () => {
      expect(publicJsonWebKeyBackend.toJSON(true)).toStrictEqual(publicParameters);
      expect(publicJsonWebKeyBackend.parameters).toStrictEqual(publicParameters);
    });

    it("should return the Public JSON Web Key Parameters of the Private Key when exportPrivate is undefined.", () => {
      expect(privateJsonWebKeyBackend.toJSON()).toStrictEqual(publicParameters);
      expect(privateJsonWebKeyBackend.parameters).toStrictEqual(privateParameters);
    });

    it("should return the Public JSON Web Key Parameters of the Private Key when exportPrivate is false.", () => {
      expect(privateJsonWebKeyBackend.toJSON(false)).toStrictEqual(publicParameters);
      expect(privateJsonWebKeyBackend.parameters).toStrictEqual(privateParameters);
    });

    it("should return the Private JSON Web Key Parameters of the Private Key when exportPrivate is true.", () => {
      expect(privateJsonWebKeyBackend.toJSON(true)).toStrictEqual(privateParameters);
      expect(privateJsonWebKeyBackend.parameters).toStrictEqual(privateParameters);
    });
  });
});
