import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { DEFCompressionBackend } from "./def.compression.backend.ts";

describe("DEF Compression Backend", () => {
  const backend = new DEFCompressionBackend();
  const plaintext = Buffer.from("Super secret message.", "utf8");

  describe("DEF", () => {
    const compressedPlaintext = Buffer.from("Cy4tSC1SKE5NLkotUchNLS5OTE_VAwA", "base64url");

    describe("compress()", () => {
      it("should compress the provided Plaintext.", async () => {
        await expect(backend.compress(plaintext)).resolves.toStrictEqual(compressedPlaintext);
      });
    });

    describe("decompress()", () => {
      it("should decompress the provided Plaintext.", async () => {
        await expect(backend.decompress(compressedPlaintext)).resolves.toStrictEqual(plaintext);
      });
    });
  });
});
