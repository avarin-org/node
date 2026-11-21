import { Buffer } from "node:buffer";
import { timingSafeEqual } from "node:crypto";

// oxlint-disable-next-line typescript/no-namespace
export namespace Strings {
  /**
   * Checks if the provided data is a non-empty string.
   *
   * @param data Data to be checked.
   * @returns Whether or not the provided data is a non-empty string.
   */
  export function isNonEmpty(data: unknown): data is string {
    return typeof data === "string" && data.trim() !== "";
  }

  /**
   * Compares two sensitive strings by preventing timing attacks.
   *
   * @default encoding "utf8"
   * @param left First string to be compared.
   * @param right Second string to be compared.
   * @param encoding Optional encoding of the strings.
   * @returns Result of the comparison.
   */
  export function compare(left: string, right: string, encoding: NodeJS.BufferEncoding = "utf8"): boolean {
    return left.length === right.length && timingSafeEqual(Buffer.from(left, encoding), Buffer.from(right, encoding));
  }
}
