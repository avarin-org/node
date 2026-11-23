import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { InvalidJsonWebKeyError } from "../../../errors/invalid-jsonwebkey.error.ts";
import { InvalidJsonWebSignatureError } from "../../../errors/invalid-jsonwebsignature.error.ts";
import { JsonWebKey } from "../../../jwk/jsonwebkey.ts";
import type { DigitalSignatureAlgorithm } from "../digital-signature-algorithm.type.ts";
import { NoneDigitalSignatureBackend } from "./none.digital-signature.backend.ts";

const invalidJsonWebKeys: any[] = [
  undefined,
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
  new JsonWebKey({ k: "qDM80igvja4Tg_tNsEuWDhl2bMM6_NgJEldFhIEuwqQ", kty: "oct" }),
];

describe("None Digital Signature Backend", () => {
  const message = Buffer.from("Super secret message.", "utf8");

  describe("none", () => {
    const backend = new NoneDigitalSignatureBackend();

    const nullJsonWebKey = null;
    const signature = Buffer.alloc(0);

    const wrongSignature = Buffer.from("oYyAwnx7D5WIo3L1WWx_zBSNX12nH8lwXQHgpPiApSk", "base64url");

    describe("name", () => {
      it('should have "none" as its value.', () => {
        expect(backend.name).toBe<DigitalSignatureAlgorithm>("none");
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

      it("should sign the provided Message.", async () => {
        await expect(backend.sign(message, nullJsonWebKey)).resolves.toStrictEqual(signature);
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

      it("should throw when the provided Signature is invalid.", async () => {
        const error = new InvalidJsonWebSignatureError("The provided JSON Web Signature is invalid.");
        await expect(backend.verify(wrongSignature, message, nullJsonWebKey)).rejects.toThrow(error);
      });

      it("should not throw when the provided Signature matches the provided Message.", async () => {
        await expect(backend.verify(signature, message, nullJsonWebKey)).resolves.not.toThrow();
      });
    });
  });
});
