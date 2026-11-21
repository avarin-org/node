import { Buffer } from "node:buffer";
import { KeyObject } from "node:crypto";
import type { KeyObjectType } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import { JsonWebKeyBackend } from "../jsonwebkey.backend.ts";
import { RsaJsonWebKeyBackend } from "./rsa.jsonwebkey.backend.ts";
import type { RsaJsonWebKeyParameters } from "./rsa.jsonwebkey.parameters.ts";

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

const invalidModuli: any[] = [
  undefined,
  null,
  true,
  1.2,
  1n,
  "a",
  Symbol("foo"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  2047,
];

const invalidPublicExponents: any[] = [
  undefined,
  null,
  true,
  1.2,
  1n,
  "a",
  Symbol("foo"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  -1,
  0,
];

const invalidNs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol("a"), Buffer, Buffer.alloc(1), () => 1, {}, [], ""];
const invalidEs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol("a"), Buffer, Buffer.alloc(1), () => 1, {}, [], ""];
const invalidDs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol("a"), Buffer, Buffer.alloc(1), () => 1, {}, [], ""];
const invalidPs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol("a"), Buffer, Buffer.alloc(1), () => 1, {}, [], ""];
const invalidQs: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol("a"), Buffer, Buffer.alloc(1), () => 1, {}, [], ""];

const invalidDPs: any[] = [
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
];

const invalidDQs: any[] = [
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
];

const invalidQIs: any[] = [
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
];

describe("RSA JSON Web Key Backend", () => {
  const publicParameters: RsaJsonWebKeyParameters = {
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

  const privateParameters: RsaJsonWebKeyParameters = {
    ...publicParameters,
    d:
      "cc2YrWia9LGRad0SMe0PrlmeeHSyRe5-u--QJcP4uF_5LYYzXIsjDJ9_iYh0S_YY" +
      "e6bLjqHOSp44OHvJqoXMX5j3-ECKnNjnUHMtRB2awXGBqBOhB8TqoQXgmXDi1jx_" +
      "6Fu8xH-vaSfpwrsN-0QzIcYHil6b8hwE0f0r6istBmL7iayJbnONp7na9ow2fUQl" +
      "nr41vsHZa4knTZ2E2kq5ntgaXlF6AIdc4DD_BZpf2alEbhQMX9T168ZsSyAs7wKS" +
      "d3ivhHRQayXEapUfZ_ykvnF4-DoVI1iRoowgZ-dlnv4Ff3YrKQ3Zv3uHJcF1BtWQ" +
      "VipOIHx4GyIc4bmTSA5PEQ",
    dp:
      "vqtDX-2DjgtZY_3Y-eiJMRBjmVgfiZ4r1RWjrCddWEVrauafPVKULy6F09s6tqnq" +
      "rqvBgjZk0ROtgCCHZB0NNRNqkdlJWUP1vWdDsf8FyjBfU_J2OlmSOOydV_zjVbX_" +
      "-vumYUsN2M5b3Vk1nmiLgplryhLq_JDzghnnqG6CN-0",
    dq:
      "tKczxBhSwbcpu5i70fLH1iJ5BNAkSyTbdSCNYQYAqKee2Elo76lbhixmuP6upIdb" +
      "SHO9mZd8qov0MXTV1lEOrNc2KbH5HTkb1wRZ1dwlReDFdKUxxjYBtb9zpM93_XVx" +
      "btSgPPbnBBL-S_OCPVtyzS_f-49hGoF52KHGns3v0hE",
    p:
      "-ZFuDg38cG-e5L6h1Jbn8ngifWgHx8m1gybkY7yEpU1V02fvQAMI1XG-1WpZm2xj" +
      "j218wNCj0BCEdmdBqZMk5RlzLagtfzQ3rPO-ucYPZ_SDmy8Udzr-sZLCqMFyLtxk" +
      "gMfGo4QZ6UJWYpTCCmZ92nS_pa4ePrQdlpnS4DLv_SM",
    q:
      "y1YdZtsbYfCOdsYBZrDpcvubwMN2fKRAzETYW5sqYv8XkxHG1J1zHH-zWJBQfZhT" +
      "biHPgHvoaFykEm9xhuA77RFGRXxFUrGBtfqIx_OG-kRWudmH83EyMzMoKQaW98RX" +
      "WqRO1JDlcs4_vzf_KN63zQKv5i4UdiiObQkZCYIOVUk",
    qi:
      "C4q9uIi-1fYhE0NTWVNzdhSi7fA3uznTWaW1X5LWBF4gBOcWvMMTfOZEaPjtY2WP" +
      "XaTWU4bdVN0GgktVLUDPLrSj533W1cOQZb_mm_7BFNrleelruT87bZhWPYQ979kl" +
      "6590ySgbH81pEM8FQW1JBATz0MYtUNZAt8N360vayE4",
  };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("keyType", () => {
    it('should have "RSA" as its value.', () => {
      expect(RsaJsonWebKeyBackend.keyType).toBe<RsaJsonWebKeyParameters["kty"]>("RSA");
    });
  });

  describe("constructor", () => {
    let superValidateSpy: Mock<(parameters: any) => void>;

    beforeEach(() => {
      superValidateSpy = vi.spyOn(JsonWebKeyBackend.prototype, "validate");
    });

    it.each(invalidNs)('should throw when the provided JSON Web Key Parameter "n" is invalid.', (n) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "n".');

      expect(() => new RsaJsonWebKeyBackend({ ...publicParameters, n })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it.each(invalidEs)('should throw when the provided JSON Web Key Parameter "e" is invalid.', (e) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "e".');

      expect(() => new RsaJsonWebKeyBackend({ ...publicParameters, e })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it.each(invalidDs)('should throw when the provided JSON Web Key Parameter "d" is invalid.', (d) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "d".');

      expect(() => new RsaJsonWebKeyBackend({ ...privateParameters, d })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it.each(invalidPs)('should throw when the provided JSON Web Key Parameter "p" is invalid.', (p) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "p".');

      expect(() => new RsaJsonWebKeyBackend({ ...privateParameters, p })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it.each(invalidQs)('should throw when the provided JSON Web Key Parameter "q" is invalid.', (q) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "q".');

      expect(() => new RsaJsonWebKeyBackend({ ...privateParameters, q })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it.each(invalidDPs)('should throw when the provided JSON Web Key Parameter "dp" is invalid.', (dp) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "dp".');

      expect(() => new RsaJsonWebKeyBackend({ ...privateParameters, dp })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it.each(invalidDQs)('should throw when the provided JSON Web Key Parameter "dq" is invalid.', (dq) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "dq".');

      expect(() => new RsaJsonWebKeyBackend({ ...privateParameters, dq })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it.each(invalidQIs)('should throw when the provided JSON Web Key Parameter "qi" is invalid.', (qi) => {
      const error = new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "qi".');

      expect(() => new RsaJsonWebKeyBackend({ ...privateParameters, qi })).toThrow(error);
      expect(superValidateSpy).not.toHaveBeenCalled();
    });

    it.each([publicParameters, privateParameters])(
      "should return an instance of an RSA JSON Web Key Backend.",
      (parameters) => {
        let backend!: RsaJsonWebKeyBackend;

        expect(() => (backend = new RsaJsonWebKeyBackend(parameters))).not.toThrow();

        expect(backend).toBeInstanceOf(RsaJsonWebKeyBackend);
        expect(backend.parameters).toStrictEqual(parameters);

        expect(superValidateSpy).toHaveBeenCalledExactlyOnceWith(parameters);
      },
    );
  });

  describe("generate()", () => {
    it.each(invalidGenerateOptions)(
      "should throw when the provided RSA JSON Web Key Generation Options is invalid.",
      async (options) => {
        const error = new TypeError("The provided RSA JSON Web Key Generation Options is invalid.");
        await expect(RsaJsonWebKeyBackend.generate(options)).rejects.toThrow(error);
      },
    );

    it.each(invalidModuli)(
      'should throw when the provided RSA JSON Web Key Generation Option "modulus" is invalid.',
      async (modulus) => {
        const error = new TypeError('The provided RSA JSON Web Key Generation Option "modulus" is invalid.');
        await expect(RsaJsonWebKeyBackend.generate({ modulus })).rejects.toThrow(error);
      },
    );

    it.each(invalidPublicExponents)(
      'should throw when the provided RSA JSON Web Key Generation Option "publicExponent" is invalid.',
      async (publicExponent) => {
        const error = new TypeError('The provided RSA JSON Web Key Generation Option "publicExponent" is invalid.');
        await expect(RsaJsonWebKeyBackend.generate({ modulus: 2048, publicExponent })).rejects.toThrow(error);
      },
    );

    it("should return the generated Private RSA JSON Web Key.", async () => {
      let jsonWebKey!: JsonWebKey<RsaJsonWebKeyParameters>;

      await expect(
        (async () => {
          jsonWebKey = await RsaJsonWebKeyBackend.generate({ modulus: 2048 });
        })(),
      ).resolves.not.toThrow();

      expect(jsonWebKey).toBeInstanceOf(JsonWebKey);
      expect(jsonWebKey.toJSON(true)).toStrictEqual<RsaJsonWebKeyParameters>({
        d: expect.any(String),
        dp: expect.any(String),
        dq: expect.any(String),
        e: "AQAB",
        kty: "RSA",
        n: expect.any(String),
        p: expect.any(String),
        q: expect.any(String),
        qi: expect.any(String),
      });
    });

    it("should return the generated Private RSA JSON Web Key with the provided additional JSON Web Key Parameters.", async () => {
      let jsonWebKey!: JsonWebKey<RsaJsonWebKeyParameters>;

      await expect(
        (async () => {
          jsonWebKey = await RsaJsonWebKeyBackend.generate(
            { modulus: 2048 },
            { alg: "RS256", kid: "5j6S2T2zAp5YLxHO", kty: "EC" },
          );
        })(),
      ).resolves.not.toThrow();

      expect(jsonWebKey).toBeInstanceOf(JsonWebKey);
      expect(jsonWebKey.toJSON(true)).toStrictEqual<RsaJsonWebKeyParameters>({
        alg: "RS256",
        d: expect.any(String),
        dp: expect.any(String),
        dq: expect.any(String),
        e: "AQAB",
        kid: "5j6S2T2zAp5YLxHO",
        kty: "RSA",
        n: expect.any(String),
        p: expect.any(String),
        q: expect.any(String),
        qi: expect.any(String),
      });
    });
  });

  describe("getCryptoKey()", () => {
    it("should return a Public Native Crypto Key.", () => {
      let cryptoKey!: KeyObject;
      const backend = new RsaJsonWebKeyBackend(publicParameters);

      expect(() => (cryptoKey = backend.getCryptoKey())).not.toThrow();

      expect(cryptoKey).toBeInstanceOf(KeyObject);
      expect(cryptoKey.type).toBe<KeyObjectType>("public");
      expect(cryptoKey.export({ format: "jwk" })).toStrictEqual(publicParameters);
    });

    it("should return a Private Native Crypto Key.", () => {
      let cryptoKey!: KeyObject;
      const backend = new RsaJsonWebKeyBackend(privateParameters);

      expect(() => (cryptoKey = backend.getCryptoKey())).not.toThrow();

      expect(cryptoKey).toBeInstanceOf(KeyObject);
      expect(cryptoKey.type).toBe<KeyObjectType>("private");
      expect(cryptoKey.export({ format: "jwk" })).toStrictEqual(privateParameters);
    });
  });

  describe("toJSON()", () => {
    const publicJsonWebKeyBackend = new RsaJsonWebKeyBackend(publicParameters);
    const privateJsonWebKeyBackend = new RsaJsonWebKeyBackend(privateParameters);

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
