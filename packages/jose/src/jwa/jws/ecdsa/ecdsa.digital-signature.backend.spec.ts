import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import { InvalidJsonWebSignatureError } from "../../../errors/invalid-jsonwebsignature.error.ts";
import { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import type { EllipticCurveJsonWebKeyParameters } from "../../jwk/ec/elliptic-curve.jsonwebkey.parameters.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import type { DigitalSignatureAlgorithm } from "../digital-signature-algorithm.type.ts";
import { ECDSADigitalSignatureBackend } from "./ecdsa.digital-signature.backend.ts";

const invalidJsonWebKeys: any[] = [
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
];

describe("ECDSA Digital Signature Backend.", () => {
  const message = Buffer.from("Super secret message.", "utf8");

  const wrongAlgJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
    alg: "ECDH-ES",
    crv: "P-256",
    kty: "EC",
    x: "4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og",
    y: "mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8",
  });

  const wrongKtyJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
    k: "la7U9KFcv2g17jSil25USwufXL2J_5UtDadwtcIUOU40n93dzZtwKpwajuqd9XMvGW1K_vn2_ygwbZUM7oAuOw",
    kty: "oct",
  });

  const wrongSignature = Buffer.from("APwj7CgHdXxQsdUFm-JpLib8ufFZMWM0JeG7OboIhKc", "base64url");
  const wrongMessage = Buffer.from("Bad message.", "utf8");

  describe("ES256", () => {
    const backend = new ECDSADigitalSignatureBackend("ES256");

    const publicJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
      crv: "P-256",
      kty: "EC",
      x: "4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og",
      y: "mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8",
    });

    const privateJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
      ...publicJsonWebKey.parameters,
      d: "bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo",
    });

    let signature!: Buffer;

    const wrongCrvJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
      crv: "secp256k1",
      d: "nwW3RLFW8c3kxI8d6SrH6mB6UwlqcyOr5HZL-oprBTk",
      kty: "EC",
      x: "cVoZG6ar2ubapq6oQY4PmfQBJxA0KSpdD9a9Zrh7LDs",
      y: "X4-9Mjy0NMjTQTdZFuG3xYd52ClKShWrKTaJkXxgdN4",
    });

    const wrongJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
      crv: "P-256",
      kty: "EC",
      x: "P8dDVG6zFfWf7vw7piJI9SIZuQVwnG4HLhs6FHHab-Y",
      y: "YR7lER3XShyUV9ORdSBrPYyDz83YluVuPGcMc_nimhE",
    });

    describe("name", () => {
      it('should have "ES256" as its value.', () => {
        expect(backend.name).toBe<DigitalSignatureAlgorithm>("ES256");
      });
    });

    describe("sign()", () => {
      it.each(invalidJsonWebKeys)(
        "should throw when the provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
        async (jsonWebKey) => {
          const error = new InvalidJsonWebKeyError(
            "The provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
          );

          await expect(backend.sign(message, jsonWebKey)).rejects.toThrow(error);
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Digital Signature Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
        );

        await expect(backend.sign(message, wrongAlgJsonWebKey)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "EC" JSON Web Keys.');
        await expect(backend.sign(message, wrongKtyJsonWebKey as any)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "crv" must be "P-256".');
        await expect(backend.sign(message, wrongCrvJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is not a Private Key.", async () => {
        const error = new InvalidJsonWebKeyError("The provided JSON Web Key cannot be used to sign a Message.");
        await expect(backend.sign(message, publicJsonWebKey)).rejects.toThrow(error);
      });

      it("should sign the provided Message.", async () => {
        await expect(
          (async () => {
            signature = await backend.sign(message, privateJsonWebKey);
          })(),
        ).resolves.not.toThrow();

        expect(signature).toBeInstanceOf(Buffer);
        expect(signature).toHaveLength(64);
      });
    });

    describe("verify()", () => {
      it.each(invalidJsonWebKeys)(
        "should throw when the provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
        async (jsonwebkey) => {
          const error = new InvalidJsonWebKeyError(
            "The provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
          );

          await expect(backend.verify(signature, message, jsonwebkey)).rejects.toThrow(error);
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Digital Signature Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
        );

        await expect(backend.verify(signature, message, wrongAlgJsonWebKey)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "EC" JSON Web Keys.');
        await expect(backend.verify(signature, message, wrongKtyJsonWebKey as any)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "crv" must be "P-256".');
        await expect(backend.verify(signature, message, wrongCrvJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided Signature is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(wrongSignature, message, publicJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided Message is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(signature, wrongMessage, publicJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(signature, message, wrongJsonWebKey)).rejects.toThrow(error);
      });

      it("should not throw when the provided Signature matches the provided Message.", async () => {
        await expect(backend.verify(signature, message, publicJsonWebKey)).resolves.not.toThrow();
      });
    });
  });

  describe("ES384", () => {
    const backend = new ECDSADigitalSignatureBackend("ES384");

    const publicJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
      crv: "P-384",
      kty: "EC",
      x: "WQHUcjVyE63vMl-SJNYYmqgYkJKkNGOctFcD368nyI2DogjP-34teV5KUZo82AxT",
      y: "T4hHQx5WkQxjInUkQ1mMBu9iOw_ICOC5wh8QP79BRi-UPYfMP0z7b-LODdijwwFb",
    });

    const privateJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
      ...publicJsonWebKey.parameters,
      d: "Sp2paYMyI8y4oWP7GfQXaSyaoFjyd-9IvqnQlAWAdYg_z-45Q809-_kgR47c15X2",
    });

    let signature!: Buffer;

    const wrongCrvJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
      crv: "P-521",
      d: "AdTlQfG5YXpKKdb8ryx4k4Wn-MQN8KgPdfMkOFEs56c5phlEXPnu7nsOszCzkWQ5V9cL7GvDo5KSgDg0P8eYhfv4",
      kty: "EC",
      x: "AcQkwaU8dBVZygHPgR7uukQGwy1SHMbM3bkXWnC3gDm6I_OW5RQgadCWSbZ1e2wV4fZWw1YaspSU8qwmZ1_jKDNt",
      y: "ADU7z6Rqkp2EJRzcNPw_-EmKyLS79zNoGyFVFNR0WTjmUopRk6xEZz6wW_ELgllOuTEuAkneRupjGNgObgpJJxNN",
    });

    const wrongJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
      crv: "P-384",
      kty: "EC",
      x: "ZFxBkTpoI0DvV_kEr44wLvepCFj7xQBPOwHk-UjxY8MQUsqq-vImHKJ5hZwj5wNx",
      y: "O48vaT-Wt1bRU1kR7mDAV59RVn5mDbp901Zu3qJr6OTgAbi-TuvPwa4Bg3e2d4Fv",
    });

    describe("name", () => {
      it('should have "ES384" as its value.', () => {
        expect(backend.name).toBe<DigitalSignatureAlgorithm>("ES384");
      });
    });

    describe("sign()", () => {
      it.each(invalidJsonWebKeys)(
        "should throw when the provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
        async (jsonWebKey) => {
          const error = new InvalidJsonWebKeyError(
            "The provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
          );

          await expect(backend.sign(message, jsonWebKey)).rejects.toThrow(error);
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Digital Signature Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
        );

        await expect(backend.sign(message, wrongAlgJsonWebKey)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "EC" JSON Web Keys.');
        await expect(backend.sign(message, wrongKtyJsonWebKey as any)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "crv" must be "P-384".');
        await expect(backend.sign(message, wrongCrvJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is not a Private Key.", async () => {
        const error = new InvalidJsonWebKeyError("The provided JSON Web Key cannot be used to sign a Message.");
        await expect(backend.sign(message, publicJsonWebKey)).rejects.toThrow(error);
      });

      it("should sign the provided Message.", async () => {
        await expect(
          (async () => {
            signature = await backend.sign(message, privateJsonWebKey);
          })(),
        ).resolves.not.toThrow();

        expect(signature).toBeInstanceOf(Buffer);
        expect(signature).toHaveLength(96);
      });
    });

    describe("verify()", () => {
      it.each(invalidJsonWebKeys)(
        "should throw when the provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
        async (jsonWebKey) => {
          const error = new InvalidJsonWebKeyError(
            "The provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
          );

          await expect(backend.verify(signature, message, jsonWebKey)).rejects.toThrow(error);
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Digital Signature Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
        );

        await expect(backend.verify(signature, message, wrongAlgJsonWebKey)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "EC" JSON Web Keys.');
        await expect(backend.verify(signature, message, wrongKtyJsonWebKey as any)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "crv" must be "P-384".');
        await expect(backend.verify(signature, message, wrongCrvJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided Signature is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(wrongSignature, message, publicJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided Message is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(signature, wrongMessage, publicJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(signature, message, wrongJsonWebKey)).rejects.toThrow(error);
      });

      it("should not throw when the provided Signature matches the provided Message.", async () => {
        await expect(backend.verify(signature, message, publicJsonWebKey)).resolves.not.toThrow();
      });
    });
  });

  describe("ES512", () => {
    const backend = new ECDSADigitalSignatureBackend("ES512");

    const publicJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
      crv: "P-521",
      kty: "EC",
      x: "AcQkwaU8dBVZygHPgR7uukQGwy1SHMbM3bkXWnC3gDm6I_OW5RQgadCWSbZ1e2wV4fZWw1YaspSU8qwmZ1_jKDNt",
      y: "ADU7z6Rqkp2EJRzcNPw_-EmKyLS79zNoGyFVFNR0WTjmUopRk6xEZz6wW_ELgllOuTEuAkneRupjGNgObgpJJxNN",
    });

    const privateJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
      ...publicJsonWebKey.parameters,
      d: "AdTlQfG5YXpKKdb8ryx4k4Wn-MQN8KgPdfMkOFEs56c5phlEXPnu7nsOszCzkWQ5V9cL7GvDo5KSgDg0P8eYhfv4",
    });

    let signature!: Buffer;

    const wrongCrvJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
      crv: "P-256",
      d: "bwVX6Vx-TOfGKYOPAcu2xhaj3JUzs-McsC-suaHnFBo",
      kty: "EC",
      x: "4c_cS6IT6jaVQeobt_6BDCTmzBaBOTmmiSCpjd5a6Og",
      y: "mnrPnCFTDkGdEwilabaqM7DzwlAFgetZTmP9ycHPxF8",
    });

    const wrongJsonWebKey = new JsonWebKey<EllipticCurveJsonWebKeyParameters>({
      crv: "P-521",
      kty: "EC",
      x: "Abrl89-OjKQ3JaTXeDQdfhho-y3pdS-lYy0M26kVp6mUDkNJHhN_sjLfUnWngXwJc7Wpin5OnQ2Q9SdEcCZ-YwH0",
      y: "AaQyradiKRKjW3AQXaiKkneqkEE-TUg1iPl3qbrXQPcINAniE5m3kU16w-27Xn-_0oksqx6AgltGdlrr0M3RuEu1",
    });

    describe("name", () => {
      it('should have "ES512" as its value.', () => {
        expect(backend.name).toBe<DigitalSignatureAlgorithm>("ES512");
      });
    });

    describe("sign()", () => {
      it.each(invalidJsonWebKeys)(
        "should throw when the provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
        async (jsonWebKey) => {
          const error = new InvalidJsonWebKeyError(
            "The provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
          );

          await expect(backend.sign(message, jsonWebKey)).rejects.toThrow(error);
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Digital Signature Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
        );

        await expect(backend.sign(message, wrongAlgJsonWebKey)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "EC" JSON Web Keys.');
        await expect(backend.sign(message, wrongKtyJsonWebKey as any)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "crv" must be "P-521".');
        await expect(backend.sign(message, wrongCrvJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is not a Private Key.", async () => {
        const error = new InvalidJsonWebKeyError("The provided JSON Web Key cannot be used to sign a Message.");
        await expect(backend.sign(message, publicJsonWebKey)).rejects.toThrow(error);
      });

      it("should sign the provided Message.", async () => {
        await expect(
          (async () => {
            signature = await backend.sign(message, privateJsonWebKey);
          })(),
        ).resolves.not.toThrow();

        expect(signature).toBeInstanceOf(Buffer);
        expect(signature).toHaveLength(132);
      });
    });

    describe("verify()", () => {
      it.each(invalidJsonWebKeys)(
        "should throw when the provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
        async (jsonWebKey) => {
          const error = new InvalidJsonWebKeyError(
            "The provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
          );

          await expect(backend.verify(signature, message, jsonWebKey)).rejects.toThrow(error);
        },
      );

      it('should throw when the provided JSON Web Key Parameter "alg" does not match the Digital Signature Algorithm.', async () => {
        const error = new InvalidJsonWebKeyError(
          "The provided JSON Web Key cannot be used by the Digital Signature Algorithm.",
        );

        await expect(backend.verify(signature, message, wrongAlgJsonWebKey)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "kty" does not match the required JSON Web Key Key Type.', async () => {
        const error = new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "EC" JSON Web Keys.');
        await expect(backend.verify(signature, message, wrongKtyJsonWebKey as any)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "crv" does not match the required JSON Web Key Elliptic Curve.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "crv" must be "P-521".');
        await expect(backend.verify(signature, message, wrongCrvJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided Signature is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(wrongSignature, message, publicJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided Message is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(signature, wrongMessage, publicJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(signature, message, wrongJsonWebKey)).rejects.toThrow(error);
      });

      it("should not throw when the provided Signature matches the provided Message.", async () => {
        await expect(backend.verify(signature, message, publicJsonWebKey)).resolves.not.toThrow();
      });
    });
  });
});
