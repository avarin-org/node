import { Buffer } from "node:buffer";
import * as crypto from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { InvalidJoseHeaderError } from "../../../../errors/invalid-jose-header.error.ts";
import { InvalidJsonWebKeyError } from "../../../../errors/invalid-jsonwebkey.error.ts";
import { JsonWebEncryptionHeader } from "../../../../jwe/header/jsonwebencryption.header.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { EllipticCurveJsonWebKeyParameters } from "../../../jwk/ec/elliptic-curve.jsonwebkey.parameters.ts";
import type { RsaJsonWebKeyParameters } from "../../../jwk/rsa/rsa.jsonwebkey.parameters.ts";
import { AESKWKeyManagementBackend } from "../aeskw/aeskw.key-management.backend.ts";
import type { KeyManagementAlgorithm } from "../key-management-algorithm.type.ts";
import type { ECDHESJsonWebEncryptionHeaderParameters } from "./ecdhes.jsonwebencryption.header.parameters.ts";
import { ECDHESKeyManagementBackend } from "./ecdhes.key-management.backend.ts";

vi.mock(import("node:crypto"), async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, randomBytes: vi.fn() };
});

const aliceJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
  crv: "P-256",
  d: "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
  kty: "EC",
  x: "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
  y: "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
});

const bobJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
  crv: "P-256",
  d: "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
  kty: "EC",
  x: "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
  y: "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
});

const wrongKtyJsonWebKey = new JsonWebKey<RsaJsonWebKeyParameters>({
  e: "AQAB",
  kty: "RSA",
  n:
    "xjpFydzTbByzL5jhEa2yQO63dpS9d9SKaN107AR69skKiTR4uK1c4SzDt4YcurDB" +
    "yhgKNzeBo6Vq3IRrkrltp97LKWfeZdM-leGt8-UTZEWqrNf3UGOEj8kI6lbjiG-S" +
    "n_yNHcVA9qBV22norZkgXctHLeFbY6TmpD-I8_UiplZUHoc9KlYc7crCQRa-O7tK" +
    "FDULNTMjjifc0dmuYP7ZcYAZXmRmoOpQuDr8s7OZY7TAqN0btMfA7RpUCWLT6TMR" +
    "QPX8GcyTxfbkOrSTFueKMHVNdXDtl068XXJ9mkjORiEmwlzqSBoxdeLWcNf_u20S" +
    "5JG5iK0nsm1uZYu-02XN-w",
});

const invalidEpks: any[] = [
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
  {},
  { kty: "a" },
  aliceJsonWebKey.parameters,
  { ...aliceJsonWebKey.toJSON(), alg: "unknown" },
  { ...aliceJsonWebKey.toJSON(), alg: "ES256" },
  wrongKtyJsonWebKey.parameters,
];

const invalidApus: any[] = [
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

const invalidApvs: any[] = [
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

describe("ECDH-ES Key Management Backend", () => {
  const wrongAlgJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
    ...bobJsonWebKey.parameters,
    alg: "ES256",
  });

  const wrongJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
    crv: "P-384",
    d: "Sp2paYMyI8y4oWP7GfQXaSyaoFjyd-9IvqnQlAWAdYg_z-45Q809-_kgR47c15X2",
    kty: "EC",
    x: "WQHUcjVyE63vMl-SJNYYmqgYkJKkNGOctFcD368nyI2DogjP-34teV5KUZo82AxT",
    y: "T4hHQx5WkQxjInUkQ1mMBu9iOw_ICOC5wh8QP79BRi-UPYfMP0z7b-LODdijwwFb",
  });

  beforeEach(() => {
    vi.mocked(crypto.randomBytes).mockImplementation((size, cb) =>
      cb(null, size === 12 ? Buffer.alloc(12, 0x00) : Buffer.from([...Array.from({ length: size }).keys()])),
    );
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe("ECDH-ES", () => {
    const backend = new ECDHESKeyManagementBackend("ECDH-ES");

    const contentEncryptionKey128Bits = Buffer.from("u5erXQ6FbY-PwD4mWyQqfQ", "base64url");
    const contentEncryptionKey192Bits = Buffer.from("jwOAN1qz_5uOTrKU91yJ_HuH_t4dWJQd", "base64url");
    const contentEncryptionKey256Bits = Buffer.from("sn4a5FuGA19w_9WEuHo1U71fFW7At1TNTQ909lYtNTU", "base64url");
    const apuContentEncryptionKey128Bits = Buffer.from("fbe48nuDSWsjX7kNqhQNDw", "base64url");
    const apuContentEncryptionKey192Bits = Buffer.from("VjXA7xvikgMVBTGyN2UrXmr6DQDGpMwL", "base64url");
    const apuContentEncryptionKey256Bits = Buffer.from("pE9Ty3o4pTtE6XqB_17sQhGnZQqjIX7v1pYuuAaEhKk", "base64url");
    const apvContentEncryptionKey128Bits = Buffer.from("6vQWSAsXa-gHPFXtodR62g", "base64url");
    const apvContentEncryptionKey192Bits = Buffer.from("rk4VZ0C3r_CXfVYzwsAxEGJh_aLa2tBx", "base64url");
    const apvContentEncryptionKey256Bits = Buffer.from("TOgs8CkQRcAuhE6_8dtHPsmLIA_c1Kot9ewZWKrppqc", "base64url");
    const apuAndApvContentEncryptionKey128Bits = Buffer.from("VqqN6vgjbSBcIijNcacQGg", "base64url");
    const apuAndApvContentEncryptionKey192Bits = Buffer.from("7lHSXT1M424WRVgI9WY0gf_ldevLI9Gx", "base64url");
    const apuAndApvContentEncryptionKey256Bits = Buffer.from(
      "_VpjYu4u855R2KndssmFBzkLWo9qO8FK9HxH0bWOO2A",
      "base64url",
    );

    const encryptedKey = Buffer.alloc(0);

    let header: JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>;

    const sameApuApvHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apu: "Qm9i",
      apv: "Qm9i",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const contentEncryptionKey128BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const contentEncryptionKey192BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      enc: "A192GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const contentEncryptionKey256BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      enc: "A256GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apuContentEncryptionKey128BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apu: "QWxpY2U",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apuContentEncryptionKey192BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apu: "QWxpY2U",
      enc: "A192GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apuContentEncryptionKey256BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apu: "QWxpY2U",
      enc: "A256GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apvContentEncryptionKey128BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apv: "Qm9i",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apvContentEncryptionKey192BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apv: "Qm9i",
      enc: "A192GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apvContentEncryptionKey256BitsHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apv: "Qm9i",
      enc: "A256GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apuAndApvContentEncryptionKey128BitsHeader =
      new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
        alg: "ECDH-ES",
        apu: "QWxpY2U",
        apv: "Qm9i",
        enc: "A128GCM",
        epk: aliceJsonWebKey.toJSON(),
      });

    const apuAndApvContentEncryptionKey192BitsHeader =
      new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
        alg: "ECDH-ES",
        apu: "QWxpY2U",
        apv: "Qm9i",
        enc: "A192GCM",
        epk: aliceJsonWebKey.toJSON(),
      });

    const apuAndApvContentEncryptionKey256BitsHeader =
      new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
        alg: "ECDH-ES",
        apu: "QWxpY2U",
        apv: "Qm9i",
        enc: "A256GCM",
        epk: aliceJsonWebKey.toJSON(),
      });

    beforeEach(() => {
      header = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
        alg: "ECDH-ES",
        apu: "QWxpY2U",
        apv: "Qm9i",
        enc: "A128GCM",
        epk: aliceJsonWebKey.toJSON(),
      });
    });

    describe("constructor", () => {
      it("should have an undefined AES Key Wrap JSON Web Encryption Key Management Backend.", () => {
        expect(backend["aesKeyWrapBackend"]).toBeNull();
      });
    });

    describe("wrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.wrap(contentEncryptionKey128Bits, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "EC" JSON Web Keys.');

        await expect(backend.wrap(contentEncryptionKey128Bits, wrongKtyJsonWebKey as any, header)).rejects.toThrow(
          error,
        );
      });

      it.each(invalidEpks)(
        'should throw when the provided JOSE Header Parameter "epk" is invalid.',
        async (ephemeralKey) => {
          Reflect.set(header.parameters, "epk", ephemeralKey);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
          await expect(backend.wrap(contentEncryptionKey128Bits, bobJsonWebKey, header)).rejects.toThrow(error);
        },
      );

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, "apu", apu);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apu".');
        await expect(backend.wrap(contentEncryptionKey128Bits, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, "apv", apv);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apv".');
        await expect(backend.wrap(contentEncryptionKey128Bits, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        const error = new InvalidJoseHeaderError('The JOSE Header Parameters "apu" and "apv" cannot be equal.');
        await expect(backend.wrap(contentEncryptionKey128Bits, bobJsonWebKey, sameApuApvHeader)).rejects.toThrow(error);
      });

      it("should return an empty buffer as the Encrypted Key of the 128 bits Content Encryption Key.", async () => {
        await expect(
          backend.wrap(contentEncryptionKey128Bits, bobJsonWebKey, contentEncryptionKey128BitsHeader),
        ).resolves.toStrictEqual(encryptedKey);
      });

      it("should return an empty buffer as the Encrypted Key of the 192 bits Content Encryption Key.", async () => {
        await expect(
          backend.wrap(contentEncryptionKey192Bits, bobJsonWebKey, contentEncryptionKey192BitsHeader),
        ).resolves.toStrictEqual(encryptedKey);
      });

      it("should return an empty buffer as the Encrypted Key of the 256 bits Content Encryption Key.", async () => {
        await expect(
          backend.wrap(contentEncryptionKey256Bits, bobJsonWebKey, contentEncryptionKey256BitsHeader),
        ).resolves.toStrictEqual(encryptedKey);
      });

      it('should return an empty buffer as the Encrypted Key of the 128 bits Content Encryption Key with "apu".', async () => {
        await expect(
          backend.wrap(apuContentEncryptionKey128Bits, bobJsonWebKey, apuContentEncryptionKey128BitsHeader),
        ).resolves.toStrictEqual(encryptedKey);
      });

      it('should return an empty buffer as the Encrypted Key of the 192 bits Content Encryption Key with "apu".', async () => {
        await expect(
          backend.wrap(apuContentEncryptionKey192Bits, bobJsonWebKey, apuContentEncryptionKey192BitsHeader),
        ).resolves.toStrictEqual(encryptedKey);
      });

      it('should return an empty buffer as the Encrypted Key of the 256 bits Content Encryption Key with "apu".', async () => {
        await expect(
          backend.wrap(apuContentEncryptionKey256Bits, bobJsonWebKey, apuContentEncryptionKey256BitsHeader),
        ).resolves.toStrictEqual(encryptedKey);
      });

      it('should return an empty buffer as the Encrypted Key of the 128 bits Content Encryption Key with "apv".', async () => {
        await expect(
          backend.wrap(apvContentEncryptionKey128Bits, bobJsonWebKey, apvContentEncryptionKey128BitsHeader),
        ).resolves.toStrictEqual(encryptedKey);
      });

      it('should return an empty buffer as the Encrypted Key of the 192 bits Content Encryption Key with "apv".', async () => {
        await expect(
          backend.wrap(apvContentEncryptionKey192Bits, bobJsonWebKey, apvContentEncryptionKey192BitsHeader),
        ).resolves.toStrictEqual(encryptedKey);
      });

      it('should return an empty buffer as the Encrypted Key of the 256 bits Content Encryption Key with "apv".', async () => {
        await expect(
          backend.wrap(apvContentEncryptionKey256Bits, bobJsonWebKey, apvContentEncryptionKey256BitsHeader),
        ).resolves.toStrictEqual(encryptedKey);
      });

      it('should return an empty buffer as the Encrypted Key of the 128 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.wrap(apuAndApvContentEncryptionKey128Bits, bobJsonWebKey, apuAndApvContentEncryptionKey128BitsHeader),
        ).resolves.toStrictEqual(encryptedKey);
      });

      it('should return an empty buffer as the Encrypted Key of the 192 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.wrap(apuAndApvContentEncryptionKey192Bits, bobJsonWebKey, apuAndApvContentEncryptionKey192BitsHeader),
        ).resolves.toStrictEqual(encryptedKey);
      });

      it('should return an empty buffer as the Encrypted Key of the 256 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.wrap(apuAndApvContentEncryptionKey256Bits, bobJsonWebKey, apuAndApvContentEncryptionKey256BitsHeader),
        ).resolves.toStrictEqual(encryptedKey);
      });
    });

    describe("unwrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.unwrap(encryptedKey, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "EC" JSON Web Keys.');
        await expect(backend.unwrap(encryptedKey, wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidEpks)(
        'should throw when the provided JOSE Header Parameter "epk" is invalid.',
        async (ephemeralKey) => {
          Reflect.set(header.parameters, "epk", ephemeralKey);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
          await expect(backend.unwrap(encryptedKey, bobJsonWebKey, header)).rejects.toThrow(error);
        },
      );

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, "apu", apu);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apu".');
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, "apv", apv);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apv".');
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        const error = new InvalidJoseHeaderError('The JOSE Header Parameters "apu" and "apv" cannot be equal.');
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, sameApuApvHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should return the Shared Secret as the 128 bits Content Encryption Key.", async () => {
        await expect(
          backend.unwrap(encryptedKey, bobJsonWebKey, contentEncryptionKey128BitsHeader),
        ).resolves.toStrictEqual(contentEncryptionKey128Bits);
      });

      it("should return the Shared Secret as the 192 bits Content Encryption Key.", async () => {
        await expect(
          backend.unwrap(encryptedKey, bobJsonWebKey, contentEncryptionKey192BitsHeader),
        ).resolves.toStrictEqual(contentEncryptionKey192Bits);
      });

      it("should return the Shared Secret as the 256 bits Content Encryption Key.", async () => {
        await expect(
          backend.unwrap(encryptedKey, bobJsonWebKey, contentEncryptionKey256BitsHeader),
        ).resolves.toStrictEqual(contentEncryptionKey256Bits);
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key with "apu".', async () => {
        await expect(
          backend.unwrap(encryptedKey, bobJsonWebKey, apuContentEncryptionKey128BitsHeader),
        ).resolves.toStrictEqual(apuContentEncryptionKey128Bits);
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key with "apu".', async () => {
        await expect(
          backend.unwrap(encryptedKey, bobJsonWebKey, apuContentEncryptionKey192BitsHeader),
        ).resolves.toStrictEqual(apuContentEncryptionKey192Bits);
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key with "apu".', async () => {
        await expect(
          backend.unwrap(encryptedKey, bobJsonWebKey, apuContentEncryptionKey256BitsHeader),
        ).resolves.toStrictEqual(apuContentEncryptionKey256Bits);
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key with "apv".', async () => {
        await expect(
          backend.unwrap(encryptedKey, bobJsonWebKey, apvContentEncryptionKey128BitsHeader),
        ).resolves.toStrictEqual(apvContentEncryptionKey128Bits);
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key with "apv".', async () => {
        await expect(
          backend.unwrap(encryptedKey, bobJsonWebKey, apvContentEncryptionKey192BitsHeader),
        ).resolves.toStrictEqual(apvContentEncryptionKey192Bits);
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key with "apv".', async () => {
        await expect(
          backend.unwrap(encryptedKey, bobJsonWebKey, apvContentEncryptionKey256BitsHeader),
        ).resolves.toStrictEqual(apvContentEncryptionKey256Bits);
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.unwrap(encryptedKey, bobJsonWebKey, apuAndApvContentEncryptionKey128BitsHeader),
        ).resolves.toStrictEqual(apuAndApvContentEncryptionKey128Bits);
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.unwrap(encryptedKey, bobJsonWebKey, apuAndApvContentEncryptionKey192BitsHeader),
        ).resolves.toStrictEqual(apuAndApvContentEncryptionKey192Bits);
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.unwrap(encryptedKey, bobJsonWebKey, apuAndApvContentEncryptionKey256BitsHeader),
        ).resolves.toStrictEqual(apuAndApvContentEncryptionKey256Bits);
      });
    });

    describe("generateContentEncryptionKey()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.generateContentEncryptionKey(wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "EC" JSON Web Keys.');

        await expect(backend.generateContentEncryptionKey(wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidEpks)(
        'should throw when the provided JOSE Header Parameter "epk" is invalid.',
        async (ephemeralKey) => {
          Reflect.set(header.parameters, "epk", ephemeralKey);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
          await expect(backend.generateContentEncryptionKey(bobJsonWebKey, header)).rejects.toThrow(error);
        },
      );

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, "apu", apu);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apu".');
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, "apv", apv);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apv".');
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        const error = new InvalidJoseHeaderError('The JOSE Header Parameters "apu" and "apv" cannot be equal.');
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, sameApuApvHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
        await expect(backend.generateContentEncryptionKey(wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should return the Shared Secret as the 128 bits Content Encryption Key.", async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, contentEncryptionKey128BitsHeader),
        ).resolves.toStrictEqual(contentEncryptionKey128Bits);
      });

      it("should return the Shared Secret as the 192 bits Content Encryption Key.", async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, contentEncryptionKey192BitsHeader),
        ).resolves.toStrictEqual(contentEncryptionKey192Bits);
      });

      it("should return the Shared Secret as the 256 bits Content Encryption Key.", async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, contentEncryptionKey256BitsHeader),
        ).resolves.toStrictEqual(contentEncryptionKey256Bits);
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key with "apu".', async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, apuContentEncryptionKey128BitsHeader),
        ).resolves.toStrictEqual(apuContentEncryptionKey128Bits);
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key with "apu".', async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, apuContentEncryptionKey192BitsHeader),
        ).resolves.toStrictEqual(apuContentEncryptionKey192Bits);
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key with "apu".', async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, apuContentEncryptionKey256BitsHeader),
        ).resolves.toStrictEqual(apuContentEncryptionKey256Bits);
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key with "apv".', async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, apvContentEncryptionKey128BitsHeader),
        ).resolves.toStrictEqual(apvContentEncryptionKey128Bits);
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key with "apv".', async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, apvContentEncryptionKey192BitsHeader),
        ).resolves.toStrictEqual(apvContentEncryptionKey192Bits);
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key with "apv".', async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, apvContentEncryptionKey256BitsHeader),
        ).resolves.toStrictEqual(apvContentEncryptionKey256Bits);
      });

      it('should return the Shared Secret as the 128 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, apuAndApvContentEncryptionKey128BitsHeader),
        ).resolves.toStrictEqual(apuAndApvContentEncryptionKey128Bits);
      });

      it('should return the Shared Secret as the 192 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, apuAndApvContentEncryptionKey192BitsHeader),
        ).resolves.toStrictEqual(apuAndApvContentEncryptionKey192Bits);
      });

      it('should return the Shared Secret as the 256 bits Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, apuAndApvContentEncryptionKey256BitsHeader),
        ).resolves.toStrictEqual(apuAndApvContentEncryptionKey256Bits);
      });
    });
  });

  describe("ECDH-ES+A128KW", () => {
    const backend = new ECDHESKeyManagementBackend("ECDH-ES+A128KW");

    let aeskwWrapSpy: Mock<AESKWKeyManagementBackend["wrap"]>;
    let aeskwUnwrapSpy: Mock<AESKWKeyManagementBackend["unwrap"]>;

    const contentEncryptionKey = Buffer.from("AAECAwQFBgcICQoLDA0ODw", "base64url");

    const encryptedKey = Buffer.from("ebJEv4Jb76ZKe0XgbShUPWRPbGCUZetC", "base64url");
    const apuEncryptedKey = Buffer.from("jlEAlsw3BryImiRLd-anLh0GJuqC0RdL", "base64url");
    const apvEncryptedKey = Buffer.from("bewUAshl5uzADF38Cbl-imgA9FWoj-l7", "base64url");
    const apuAndApvEncryptedKey = Buffer.from("-O-0N512N8f1bIHeDte0fJLO1u2knyk2", "base64url");

    let header: JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>;

    const sameApuApvHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES+A128KW",
      apu: "Qm9i",
      apv: "Qm9i",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const encryptedKeyHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apuEncryptedKeyHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apu: "QWxpY2U",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apvEncryptedKeyHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apv: "Qm9i",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apuAndApvEncryptedKeyHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apu: "QWxpY2U",
      apv: "Qm9i",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    beforeEach(() => {
      aeskwWrapSpy = vi.spyOn(backend["aesKeyWrapBackend"]!, "wrap");
      aeskwUnwrapSpy = vi.spyOn(backend["aesKeyWrapBackend"]!, "unwrap");

      header = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
        alg: "ECDH-ES+A128KW",
        apu: "QWxpY2U",
        apv: "Qm9i",
        enc: "A128GCM",
        epk: aliceJsonWebKey.toJSON(),
      });
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    describe("constructor", () => {
      it("should have a 128-bit AES Key Wrap JSON Web Encryption Key Management Backend.", () => {
        expect(backend["aesKeyWrapBackend"]).toBeInstanceOf(AESKWKeyManagementBackend);
        expect(backend["aesKeyWrapBackend"]!.name).toBe<KeyManagementAlgorithm>("A128KW");
      });
    });

    describe("wrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.wrap(contentEncryptionKey, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "EC" JSON Web Keys.');
        await expect(backend.wrap(contentEncryptionKey, wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidEpks)(
        'should throw when the provided JOSE Header Parameter "epk" is invalid.',
        async (ephemeralKey) => {
          Reflect.set(header.parameters, "epk", ephemeralKey);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
          await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, header)).rejects.toThrow(error);
        },
      );

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, "apu", apu);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apu".');
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, "apv", apv);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apv".');
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        const error = new InvalidJoseHeaderError('The JOSE Header Parameters "apu" and "apv" cannot be equal.');
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, sameApuApvHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
        await expect(backend.wrap(contentEncryptionKey, wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should wrap the provided Content Encryption Key.", async () => {
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, encryptedKeyHeader)).resolves.toStrictEqual(
          encryptedKey,
        );

        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(
          contentEncryptionKey,
          expect.any(JsonWebKey),
          encryptedKeyHeader,
        );
      });

      it('should wrap the provided Content Encryption Key with "apu".', async () => {
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, apuEncryptedKeyHeader)).resolves.toStrictEqual(
          apuEncryptedKey,
        );

        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(
          contentEncryptionKey,
          expect.any(JsonWebKey),
          apuEncryptedKeyHeader,
        );
      });

      it('should wrap the provided Content Encryption Key with "apv".', async () => {
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, apvEncryptedKeyHeader)).resolves.toStrictEqual(
          apvEncryptedKey,
        );

        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(
          contentEncryptionKey,
          expect.any(JsonWebKey),
          apvEncryptedKeyHeader,
        );
      });

      it('should wrap the provided Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.wrap(contentEncryptionKey, bobJsonWebKey, apuAndApvEncryptedKeyHeader),
        ).resolves.toStrictEqual(apuAndApvEncryptedKey);

        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(
          contentEncryptionKey,
          expect.any(JsonWebKey),
          apuAndApvEncryptedKeyHeader,
        );
      });
    });

    describe("unwrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.unwrap(encryptedKey, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "EC" JSON Web Keys.');
        await expect(backend.unwrap(encryptedKey, wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidEpks)(
        'should throw when the provided JOSE Header Parameter "epk" is invalid.',
        async (ephemeralKey) => {
          Reflect.set(header.parameters, "epk", ephemeralKey);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
          await expect(backend.unwrap(encryptedKey, bobJsonWebKey, header)).rejects.toThrow(error);
        },
      );

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, "apu", apu);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apu".');
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, "apv", apv);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apv".');
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        const error = new InvalidJoseHeaderError('The JOSE Header Parameters "apu" and "apv" cannot be equal.');
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, sameApuApvHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should return the Content Encryption Key.", async () => {
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, encryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );

        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(
          encryptedKey,
          expect.any(JsonWebKey),
          encryptedKeyHeader,
        );
      });

      it('should return the Content Encryption Key with "apu".', async () => {
        await expect(backend.unwrap(apuEncryptedKey, bobJsonWebKey, apuEncryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );

        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(
          apuEncryptedKey,
          expect.any(JsonWebKey),
          apuEncryptedKeyHeader,
        );
      });

      it('should return the Content Encryption Key with "apv".', async () => {
        await expect(backend.unwrap(apvEncryptedKey, bobJsonWebKey, apvEncryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );

        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(
          apvEncryptedKey,
          expect.any(JsonWebKey),
          apvEncryptedKeyHeader,
        );
      });

      it('should return the Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.unwrap(apuAndApvEncryptedKey, bobJsonWebKey, apuAndApvEncryptedKeyHeader),
        ).resolves.toStrictEqual(contentEncryptionKey);

        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(
          apuAndApvEncryptedKey,
          expect.any(JsonWebKey),
          apuAndApvEncryptedKeyHeader,
        );
      });
    });

    describe("generateContentEncryptionKey()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.generateContentEncryptionKey(wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "EC" JSON Web Keys.');

        await expect(backend.generateContentEncryptionKey(wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidEpks)(
        'should throw when the provided JOSE Header Parameter "epk" is invalid.',
        async (ephemeralKey) => {
          Reflect.set(header.parameters, "epk", ephemeralKey);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
          await expect(backend.generateContentEncryptionKey(bobJsonWebKey, header)).rejects.toThrow(error);
        },
      );

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, "apu", apu);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apu".');
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, "apv", apv);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apv".');
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        const error = new InvalidJoseHeaderError('The JOSE Header Parameters "apu" and "apv" cannot be equal.');
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, sameApuApvHeader)).rejects.toThrow(error);
      });

      it("should return the Content Encryption Key.", async () => {
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, encryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });

      it('should return the Content Encryption Key with "apu".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, apuEncryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });

      it('should return the Content Encryption Key with "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, apvEncryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });

      it('should return the Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, apuAndApvEncryptedKeyHeader),
        ).resolves.toStrictEqual(contentEncryptionKey);
      });
    });
  });

  describe("ECDH-ES+A192KW", () => {
    const backend = new ECDHESKeyManagementBackend("ECDH-ES+A192KW");

    let aeskwWrapSpy: Mock<AESKWKeyManagementBackend["wrap"]>;
    let aeskwUnwrapSpy: Mock<AESKWKeyManagementBackend["unwrap"]>;

    const contentEncryptionKey = Buffer.from("AAECAwQFBgcICQoLDA0ODw", "base64url");

    const encryptedKey = Buffer.from("riTxC0UGCRV8vYCR022zskFfOMhOD-ms", "base64url");
    const apuEncryptedKey = Buffer.from("WciBje0F74ivHUXyJ_Jrydkqc2TZSbHZ", "base64url");
    const apvEncryptedKey = Buffer.from("Qb_fv3jJzG7-PQknVGP0gBo3p4o6HoSt", "base64url");
    const apuAndApvEncryptedKey = Buffer.from("Wc4q4jHLA-H3pmhufwkZ0pN3Z8w6ugdO", "base64url");

    let header: JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>;

    const sameApuApvHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES+A192KW",
      apu: "Qm9i",
      apv: "Qm9i",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const encryptedKeyHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apuEncryptedKeyHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apu: "QWxpY2U",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apvEncryptedKeyHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apv: "Qm9i",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apuAndApvEncryptedKeyHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apu: "QWxpY2U",
      apv: "Qm9i",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    beforeEach(() => {
      aeskwWrapSpy = vi.spyOn(backend["aesKeyWrapBackend"]!, "wrap");
      aeskwUnwrapSpy = vi.spyOn(backend["aesKeyWrapBackend"]!, "unwrap");

      header = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
        alg: "ECDH-ES+A192KW",
        apu: "QWxpY2U",
        apv: "Qm9i",
        enc: "A128GCM",
        epk: aliceJsonWebKey.toJSON(),
      });
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    describe("constructor", () => {
      it("should have a 192-bit AES Key Wrap JSON Web Encryption Key Management Backend.", () => {
        expect(backend["aesKeyWrapBackend"]).toBeInstanceOf(AESKWKeyManagementBackend);
        expect(backend["aesKeyWrapBackend"]!.name).toBe<KeyManagementAlgorithm>("A192KW");
      });
    });

    describe("wrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.wrap(contentEncryptionKey, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "EC" JSON Web Keys.');
        await expect(backend.wrap(contentEncryptionKey, wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidEpks)(
        'should throw when the provided JOSE Header Parameter "epk" is invalid.',
        async (ephemeralKey) => {
          Reflect.set(header.parameters, "epk", ephemeralKey);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
          await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, header)).rejects.toThrow(error);
        },
      );

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, "apu", apu);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apu".');
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, "apv", apv);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apv".');
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        const error = new InvalidJoseHeaderError('The JOSE Header Parameters "apu" and "apv" cannot be equal.');
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, sameApuApvHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
        await expect(backend.wrap(contentEncryptionKey, wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should wrap the provided Content Encryption Key.", async () => {
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, encryptedKeyHeader)).resolves.toStrictEqual(
          encryptedKey,
        );

        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(
          contentEncryptionKey,
          expect.any(JsonWebKey),
          encryptedKeyHeader,
        );
      });

      it('should wrap the provided Content Encryption Key with "apu".', async () => {
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, apuEncryptedKeyHeader)).resolves.toStrictEqual(
          apuEncryptedKey,
        );

        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(
          contentEncryptionKey,
          expect.any(JsonWebKey),
          apuEncryptedKeyHeader,
        );
      });

      it('should wrap the provided Content Encryption Key with "apv".', async () => {
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, apvEncryptedKeyHeader)).resolves.toStrictEqual(
          apvEncryptedKey,
        );

        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(
          contentEncryptionKey,
          expect.any(JsonWebKey),
          apvEncryptedKeyHeader,
        );
      });

      it('should wrap the provided Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.wrap(contentEncryptionKey, bobJsonWebKey, apuAndApvEncryptedKeyHeader),
        ).resolves.toStrictEqual(apuAndApvEncryptedKey);

        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(
          contentEncryptionKey,
          expect.any(JsonWebKey),
          apuAndApvEncryptedKeyHeader,
        );
      });
    });

    describe("unwrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.unwrap(encryptedKey, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "EC" JSON Web Keys.');
        await expect(backend.unwrap(encryptedKey, wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidEpks)(
        'should throw when the provided JOSE Header Parameter "epk" is invalid.',
        async (ephemeralKey) => {
          Reflect.set(header.parameters, "epk", ephemeralKey);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
          await expect(backend.unwrap(encryptedKey, bobJsonWebKey, header)).rejects.toThrow(error);
        },
      );

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, "apu", apu);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apu".');
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, "apv", apv);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apv".');
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        const error = new InvalidJoseHeaderError('The JOSE Header Parameters "apu" and "apv" cannot be equal.');
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, sameApuApvHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should return the Content Encryption Key.", async () => {
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, encryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );

        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(
          encryptedKey,
          expect.any(JsonWebKey),
          encryptedKeyHeader,
        );
      });

      it('should return the Content Encryption Key with "apu".', async () => {
        await expect(backend.unwrap(apuEncryptedKey, bobJsonWebKey, apuEncryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );

        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(
          apuEncryptedKey,
          expect.any(JsonWebKey),
          apuEncryptedKeyHeader,
        );
      });

      it('should return the Content Encryption Key with "apv".', async () => {
        await expect(backend.unwrap(apvEncryptedKey, bobJsonWebKey, apvEncryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );

        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(
          apvEncryptedKey,
          expect.any(JsonWebKey),
          apvEncryptedKeyHeader,
        );
      });

      it('should return the Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.unwrap(apuAndApvEncryptedKey, bobJsonWebKey, apuAndApvEncryptedKeyHeader),
        ).resolves.toStrictEqual(contentEncryptionKey);

        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(
          apuAndApvEncryptedKey,
          expect.any(JsonWebKey),
          apuAndApvEncryptedKeyHeader,
        );
      });
    });

    describe("generateContentEncryptionKey()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.generateContentEncryptionKey(wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "EC" JSON Web Keys.');

        await expect(backend.generateContentEncryptionKey(wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidEpks)(
        'should throw when the provided JOSE Header Parameter "epk" is invalid.',
        async (ephemeralKey) => {
          Reflect.set(header.parameters, "epk", ephemeralKey);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
          await expect(backend.generateContentEncryptionKey(bobJsonWebKey, header)).rejects.toThrow(error);
        },
      );

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, "apu", apu);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apu".');
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, "apv", apv);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apv".');
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        const error = new InvalidJoseHeaderError('The JOSE Header Parameters "apu" and "apv" cannot be equal.');
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, sameApuApvHeader)).rejects.toThrow(error);
      });

      it("should return the Content Encryption Key.", async () => {
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, encryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });

      it('should return the Content Encryption Key with "apu".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, apuEncryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });

      it('should return the Content Encryption Key with "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, apvEncryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });

      it('should return the Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, apuAndApvEncryptedKeyHeader),
        ).resolves.toStrictEqual(contentEncryptionKey);
      });
    });
  });

  describe("ECDH-ES+A256KW", () => {
    const backend = new ECDHESKeyManagementBackend("ECDH-ES+A256KW");

    let aeskwWrapSpy: Mock<AESKWKeyManagementBackend["wrap"]>;
    let aeskwUnwrapSpy: Mock<AESKWKeyManagementBackend["unwrap"]>;

    const contentEncryptionKey = Buffer.from("AAECAwQFBgcICQoLDA0ODw", "base64url");

    const encryptedKey = Buffer.from("gWvAv5k6x2zo61kdosw0Ztx5SHwlYUxM", "base64url");
    const apuEncryptedKey = Buffer.from("esnqpN0kPDUUwsHAvvFGz4Kd3jHRpqpm", "base64url");
    const apvEncryptedKey = Buffer.from("wlrQUCWdmF7Bi2U5Af7lF-3W1rLPwruh", "base64url");
    const apuAndApvEncryptedKey = Buffer.from("jGS3GB2G8-Yy62oWb_LoCQqqRGO9PZPt", "base64url");

    let header: JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>;

    const sameApuApvHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES+A256KW",
      apu: "Qm9i",
      apv: "Qm9i",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const encryptedKeyHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apuEncryptedKeyHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apu: "QWxpY2U",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apvEncryptedKeyHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apv: "Qm9i",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    const apuAndApvEncryptedKeyHeader = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
      alg: "ECDH-ES",
      apu: "QWxpY2U",
      apv: "Qm9i",
      enc: "A128GCM",
      epk: aliceJsonWebKey.toJSON(),
    });

    beforeEach(() => {
      aeskwWrapSpy = vi.spyOn(backend["aesKeyWrapBackend"]!, "wrap");
      aeskwUnwrapSpy = vi.spyOn(backend["aesKeyWrapBackend"]!, "unwrap");

      header = new JsonWebEncryptionHeader<ECDHESJsonWebEncryptionHeaderParameters>({
        alg: "ECDH-ES+A256KW",
        apu: "QWxpY2U",
        apv: "Qm9i",
        enc: "A128GCM",
        epk: aliceJsonWebKey.toJSON(),
      });
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    describe("constructor", () => {
      it("should have a 256-bit AES Key Wrap JSON Web Encryption Key Management Backend.", () => {
        expect(backend["aesKeyWrapBackend"]).toBeInstanceOf(AESKWKeyManagementBackend);
        expect(backend["aesKeyWrapBackend"]!.name).toBe<KeyManagementAlgorithm>("A256KW");
      });
    });

    describe("wrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.wrap(contentEncryptionKey, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "EC" JSON Web Keys.');
        await expect(backend.wrap(contentEncryptionKey, wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidEpks)(
        'should throw when the provided JOSE Header Parameter "epk" is invalid.',
        async (ephemeralKey) => {
          Reflect.set(header.parameters, "epk", ephemeralKey);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
          await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, header)).rejects.toThrow(error);
        },
      );

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, "apu", apu);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apu".');
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, "apv", apv);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apv".');
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        const error = new InvalidJoseHeaderError('The JOSE Header Parameters "apu" and "apv" cannot be equal.');
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, sameApuApvHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
        await expect(backend.wrap(contentEncryptionKey, wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should wrap the provided Content Encryption Key.", async () => {
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, encryptedKeyHeader)).resolves.toStrictEqual(
          encryptedKey,
        );

        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(
          contentEncryptionKey,
          expect.any(JsonWebKey),
          encryptedKeyHeader,
        );
      });

      it('should wrap the provided Content Encryption Key with "apu".', async () => {
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, apuEncryptedKeyHeader)).resolves.toStrictEqual(
          apuEncryptedKey,
        );

        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(
          contentEncryptionKey,
          expect.any(JsonWebKey),
          apuEncryptedKeyHeader,
        );
      });

      it('should wrap the provided Content Encryption Key with "apv".', async () => {
        await expect(backend.wrap(contentEncryptionKey, bobJsonWebKey, apvEncryptedKeyHeader)).resolves.toStrictEqual(
          apvEncryptedKey,
        );

        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(
          contentEncryptionKey,
          expect.any(JsonWebKey),
          apvEncryptedKeyHeader,
        );
      });

      it('should wrap the provided Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.wrap(contentEncryptionKey, bobJsonWebKey, apuAndApvEncryptedKeyHeader),
        ).resolves.toStrictEqual(apuAndApvEncryptedKey);

        expect(aeskwWrapSpy).toHaveBeenCalledExactlyOnceWith(
          contentEncryptionKey,
          expect.any(JsonWebKey),
          apuAndApvEncryptedKeyHeader,
        );
      });
    });

    describe("unwrap()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.unwrap(encryptedKey, wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "EC" JSON Web Keys.');
        await expect(backend.unwrap(encryptedKey, wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidEpks)(
        'should throw when the provided JOSE Header Parameter "epk" is invalid.',
        async (ephemeralKey) => {
          Reflect.set(header.parameters, "epk", ephemeralKey);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
          await expect(backend.unwrap(encryptedKey, bobJsonWebKey, header)).rejects.toThrow(error);
        },
      );

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, "apu", apu);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apu".');
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, "apv", apv);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apv".');
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        const error = new InvalidJoseHeaderError('The JOSE Header Parameters "apu" and "apv" cannot be equal.');
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, sameApuApvHeader)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameter "epk" and the provided Unwrap JSON Web Key have different Curves.', async () => {
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
        await expect(backend.unwrap(encryptedKey, wrongJsonWebKey, header)).rejects.toThrow(error);
      });

      it("should return the Content Encryption Key.", async () => {
        await expect(backend.unwrap(encryptedKey, bobJsonWebKey, encryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );

        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(
          encryptedKey,
          expect.any(JsonWebKey),
          encryptedKeyHeader,
        );
      });

      it('should return the Content Encryption Key with "apu".', async () => {
        await expect(backend.unwrap(apuEncryptedKey, bobJsonWebKey, apuEncryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );

        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(
          apuEncryptedKey,
          expect.any(JsonWebKey),
          apuEncryptedKeyHeader,
        );
      });

      it('should return the Content Encryption Key with "apv".', async () => {
        await expect(backend.unwrap(apvEncryptedKey, bobJsonWebKey, apvEncryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );

        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(
          apvEncryptedKey,
          expect.any(JsonWebKey),
          apvEncryptedKeyHeader,
        );
      });

      it('should return the Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.unwrap(apuAndApvEncryptedKey, bobJsonWebKey, apuAndApvEncryptedKeyHeader),
        ).resolves.toStrictEqual(contentEncryptionKey);

        expect(aeskwUnwrapSpy).toHaveBeenCalledExactlyOnceWith(
          apuAndApvEncryptedKey,
          expect.any(JsonWebKey),
          apuAndApvEncryptedKeyHeader,
        );
      });
    });

    describe("generateContentEncryptionKey()", () => {
      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Key Management Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Key Management Algorithm.",
        );

        await expect(backend.generateContentEncryptionKey(wrongAlgJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Key Management Algorithm only accepts "EC" JSON Web Keys.');

        await expect(backend.generateContentEncryptionKey(wrongKtyJsonWebKey as any, header)).rejects.toThrow(error);
      });

      it.each(invalidEpks)(
        'should throw when the provided JOSE Header Parameter "epk" is invalid.',
        async (ephemeralKey) => {
          Reflect.set(header.parameters, "epk", ephemeralKey);
          const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "epk".');
          await expect(backend.generateContentEncryptionKey(bobJsonWebKey, header)).rejects.toThrow(error);
        },
      );

      it.each(invalidApus)('should throw when the provided JOSE Header Parameter "apu" is invalid.', async (apu) => {
        Reflect.set(header.parameters, "apu", apu);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apu".');
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it.each(invalidApvs)('should throw when the provided JOSE Header Parameter "apv" is invalid.', async (apv) => {
        Reflect.set(header.parameters, "apv", apv);
        const error = new InvalidJoseHeaderError('Invalid JOSE Header Parameter "apv".');
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, header)).rejects.toThrow(error);
      });

      it('should throw when the provided JOSE Header Parameters "apu" and "apv" are equal.', async () => {
        const error = new InvalidJoseHeaderError('The JOSE Header Parameters "apu" and "apv" cannot be equal.');
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, sameApuApvHeader)).rejects.toThrow(error);
      });

      it("should return the Content Encryption Key.", async () => {
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, encryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });

      it('should return the Content Encryption Key with "apu".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, apuEncryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });

      it('should return the Content Encryption Key with "apv".', async () => {
        await expect(backend.generateContentEncryptionKey(bobJsonWebKey, apvEncryptedKeyHeader)).resolves.toStrictEqual(
          contentEncryptionKey,
        );
      });

      it('should return the Content Encryption Key with "apu" and "apv".', async () => {
        await expect(
          backend.generateContentEncryptionKey(bobJsonWebKey, apuAndApvEncryptedKeyHeader),
        ).resolves.toStrictEqual(contentEncryptionKey);
      });
    });
  });
});
