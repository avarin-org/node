import type { Buffer } from "node:buffer";

import type { CompressionAlgorithm } from "./compression-algorithm.type.ts";

/**
 * Implementation of the Compression Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3|RFC 7516 "zip" (Compression Algorithm) Header Parameter}
 */
export abstract class CompressionBackend {
  /**
   * Compression Algorithm.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3|RFC 7516 "zip" (Compression Algorithm) Header Parameter}
   */
  public readonly name: CompressionAlgorithm;

  /**
   * Instantiates a new Compression Backend.
   *
   * @param name Compression Algorithm.
   */
  public constructor(name: CompressionAlgorithm) {
    this.name = name;
  }

  /**
   * Compresses the provided Plaintext.
   *
   * @param plaintext Plaintext to be compressed.
   * @returns Compressed Plaintext.
   */
  public abstract compress(plaintext: Buffer): Promise<Buffer>;

  /**
   * Decompresses the provided Plaintext.
   *
   * @param plaintext Plaintext to be decompressed.
   * @returns Decompressed Plaintext.
   */
  public abstract decompress(plaintext: Buffer): Promise<Buffer>;
}
