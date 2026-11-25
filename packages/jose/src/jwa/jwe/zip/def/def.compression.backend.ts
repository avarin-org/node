import type { Buffer } from "node:buffer";
import { promisify } from "node:util";
import { deflateRaw, inflateRaw } from "node:zlib";

import { CompressionBackend } from "../compression.backend.ts";

const deflateRawAsync = promisify(deflateRaw);
const inflateRawAsync = promisify(inflateRaw);

/**
 * Implementation of the DEF Compression Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3|RFC 7516 "zip" (Compression Algorithm) Header Parameter}
 */
export class DEFCompressionBackend extends CompressionBackend {
  /**
   * Instantiates a new DEF Compression Backend.
   */
  public constructor() {
    super("DEF");
  }

  /**
   * Compresses the provided Plaintext.
   *
   * @param plaintext Plaintext to be compressed.
   * @returns Compressed Plaintext.
   */
  public async compress(plaintext: Buffer): Promise<Buffer> {
    return await deflateRawAsync(plaintext);
  }

  /**
   * Decompresses the provided Plaintext.
   *
   * @param plaintext Plaintext to be decompressed.
   * @returns Decompressed Plaintext.
   */
  public async decompress(plaintext: Buffer): Promise<Buffer> {
    return await inflateRawAsync(plaintext);
  }
}
