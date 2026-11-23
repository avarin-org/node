import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import { InvalidJsonWebSignatureError } from "../../../errors/invalid-jsonwebsignature.error.ts";
import { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import type { RsaJsonWebKeyParameters } from "../../jwk/rsa/rsa.jsonwebkey.parameters.ts";
import type { DigitalSignatureAlgorithm } from "../digital-signature-algorithm.type.ts";
import { HMACDigitalSignatureBackend } from "./hmac.digital-signature.backend.ts";

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

describe("HMAC Digital Signature Backend.", () => {
  const message = Buffer.from("Super secret message.", "utf8");

  const wrongAlgJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
    alg: "A128GCMKW",
    k: "qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ",
    kty: "oct",
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

  const wrongMessage = Buffer.from("Bad message.", "utf8");

  describe("HS256", () => {
    const backend = new HMACDigitalSignatureBackend("HS256");

    const secretJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ",
      kty: "oct",
    });

    const signature = Buffer.from("oYyAwnx7D5WIo3L1WWx_zBSNX12nH8lwXQHgpPiApSk", "base64url");

    const smallJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "_Q-5ANzs2BQcquIFnnG8bg",
      kty: "oct",
    });

    const wrongSignatures = [Buffer.alloc(0), Buffer.from("HAsYK0fb8ZooUQW4Lu1BdxEV5Ce4Pl1As7JypupdBDs", "base64url")];
    const wrongJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "wSWnJGjdIe06lRs2ITPAsFeLiVoiQGbaz415daD5kOc",
      kty: "oct",
    });

    describe("name", () => {
      it('should have "HS256" as its value.', () => {
        expect(backend.name).toBe<DigitalSignatureAlgorithm>("HS256");
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
        const error = new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.sign(message, wrongKtyJsonWebKey as any)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length smaller than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be at least 32 bytes.');
        await expect(backend.sign(message, smallJsonWebKey)).rejects.toThrow(error);
      });

      it("should sign the provided Message.", async () => {
        await expect(backend.sign(message, secretJsonWebKey)).resolves.toStrictEqual(signature);
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
        const error = new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.verify(signature, message, wrongKtyJsonWebKey as any)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length smaller than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be at least 32 bytes.');
        await expect(backend.verify(signature, message, smallJsonWebKey)).rejects.toThrow(error);
      });

      it.each(wrongSignatures)("should throw when the provided Signature is invalid.", async (wrongSignature) => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(wrongSignature, message, secretJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided Message is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(signature, wrongMessage, secretJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(signature, message, wrongJsonWebKey)).rejects.toThrow(error);
      });

      it("should not throw when the provided Signature matches the provided Message.", async () => {
        await expect(backend.verify(signature, message, secretJsonWebKey)).resolves.not.toThrow();
      });
    });
  });

  describe("HS384", () => {
    const backend = new HMACDigitalSignatureBackend("HS384");

    const secretJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "StbWgZZh28xbcPHFlyX9I4obVOyoATxvnCGRn1W3bBhnL6eUppMxBLmU4FmfkUTX",
      kty: "oct",
    });

    const signature = Buffer.from("T6XdAl5A0a28AXqtCiLM_ibT46yce8xl4C-x__EV4zgd5R1OnUsIpvFL-rm0SM8o", "base64url");

    const smallJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "VVqcFoBmovm5xodv6FmUkNboA0mVuhAW",
      kty: "oct",
    });

    const wrongSignatures = [
      Buffer.alloc(0),
      Buffer.from("1XAMTYwm3gVDQ4FyPmzeE0NqC1zfKrQjmAsd1Mb_MBke-O5wiQBVKLhGK1zhPFlR", "base64url"),
    ];

    const wrongJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "pBZgPlQEOyzG1CRdKqoKexs2B23rbZVNhWilR-PAAF6bWF70B1EActiCKZlcdOEC",
      kty: "oct",
    });

    describe("name", () => {
      it('should have "HS384" as its value.', () => {
        expect(backend.name).toBe<DigitalSignatureAlgorithm>("HS384");
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
        const error = new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.sign(message, wrongKtyJsonWebKey as any)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length smaller than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be at least 48 bytes.');
        await expect(backend.sign(message, smallJsonWebKey)).rejects.toThrow(error);
      });

      it("should sign the provided Message.", async () => {
        await expect(backend.sign(message, secretJsonWebKey)).resolves.toStrictEqual(signature);
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
        const error = new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.verify(signature, message, wrongKtyJsonWebKey as any)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length smaller than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be at least 48 bytes.');
        await expect(backend.verify(signature, message, smallJsonWebKey)).rejects.toThrow(error);
      });

      it.each(wrongSignatures)("should throw when the provided Signature is invalid.", async (wrongSignature) => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(wrongSignature, message, secretJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided Message is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(signature, wrongMessage, secretJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(signature, message, wrongJsonWebKey)).rejects.toThrow(error);
      });

      it("should not throw when the provided Signature matches the provided Message.", async () => {
        await expect(backend.verify(signature, message, secretJsonWebKey)).resolves.not.toThrow();
      });
    });
  });

  describe("HS512", () => {
    const backend = new HMACDigitalSignatureBackend("HS512");

    const secretJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "la7U9KFcv2g17jSil25USwufXL2J_5UtDadwtcIUOU40n93dzZtwKpwajuqd9XMvGW1K_vn2_ygwbZUM7oAuOw",
      kty: "oct",
    });

    const signature = Buffer.from(
      "8oHNB6v-xcTecQ22og2IVpThVQnj6ac8t3p60mxVqdpNE-QmXe9hdvJZ9YE2FieemCSWEbpwQiqJxsE-9qzKHA",
      "base64url",
    );

    const smallJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "_YXVGItuB0nw8FV-nf0WRb9tEaGy7VrlhIp0xDApPOA",
      kty: "oct",
    });

    const wrongSignatures = [
      Buffer.alloc(0),
      Buffer.from(
        "v2Lsta403z2PvG-DgWwO62Q60HnMyrozAgcM0u1Vh-y7QrgImA9ySvFPpyz-fbkORv4K3sEnhlhVe5E6tKZgFA",
        "base64url",
      ),
    ];

    const wrongJsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
      k: "SF3XK31tgbhk2P0pSHwy3ZEEOAooafH4u6W6HX__vIX4eZi-IheJQv_LoTt0OouC03VCUFBTdwNJRxDnYSGV2Q",
      kty: "oct",
    });

    describe("name", () => {
      it('should have "HS512" as its value.', () => {
        expect(backend.name).toBe<DigitalSignatureAlgorithm>("HS512");
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
        const error = new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.sign(message, wrongKtyJsonWebKey as any)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length smaller than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be at least 64 bytes.');
        await expect(backend.sign(message, smallJsonWebKey)).rejects.toThrow(error);
      });

      it("should sign the provided Message.", async () => {
        await expect(backend.sign(message, secretJsonWebKey)).resolves.toStrictEqual(signature);
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
        const error = new InvalidJsonWebKeyError('The Digital Signature Algorithm only accepts "oct" JSON Web Keys.');
        await expect(backend.verify(signature, message, wrongKtyJsonWebKey as any)).rejects.toThrow(error);
      });

      it('should throw when the provided JSON Web Key Parameter "k" has length smaller than required.', async () => {
        const error = new InvalidJsonWebKeyError('The JSON Web Key Parameter "k" must be at least 64 bytes.');
        await expect(backend.verify(signature, message, smallJsonWebKey)).rejects.toThrow(error);
      });

      it.each(wrongSignatures)("should throw when the provided Signature is invalid.", async (wrongSignature) => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(wrongSignature, message, secretJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided Message is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(signature, wrongMessage, secretJsonWebKey)).rejects.toThrow(error);
      });

      it("should throw when the provided JSON Web Key is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(signature, message, wrongJsonWebKey)).rejects.toThrow(error);
      });

      it("should not throw when the provided Signature matches the provided Message.", async () => {
        await expect(backend.verify(signature, message, secretJsonWebKey)).resolves.not.toThrow();
      });
    });
  });
});
