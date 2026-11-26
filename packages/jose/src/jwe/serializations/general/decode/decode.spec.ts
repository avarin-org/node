import { Buffer } from "node:buffer";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import { JsonWebEncryptionHeader } from "../../../header/jsonwebencryption.header.ts";
import type { GeneralJsonWebEncryptionParameters } from "../general.jsonwebencryption.parameters.ts";
import type { GeneralJsonWebEncryptionToken } from "../general.jsonwebencryption.token.ts";
import { decode } from "./decode.ts";

const fetchMock = vi.fn<typeof globalThis.fetch>();

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol("a"), Buffer, Buffer.alloc(1), () => 1, []];

const invalidTokenFormats: any[] = [
  {},
  { iv: undefined },
  { iv: null },
  { iv: true },
  { iv: 1 },
  { iv: 1.2 },
  { iv: 1n },
  { iv: Symbol("a") },
  { iv: Buffer },
  { iv: Buffer.alloc(1) },
  { iv: () => 1 },
  { iv: {} },
  { iv: [] },
  { iv: "" },
  { aad: undefined, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { aad: null, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { aad: true, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { aad: 1, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { aad: 1.2, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { aad: 1n, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { aad: Symbol("a"), iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { aad: Buffer, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { aad: Buffer.alloc(1), iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { aad: () => 1, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { aad: {}, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { aad: [], iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { aad: "", iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { ciphertext: undefined, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { ciphertext: null, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { ciphertext: true, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { ciphertext: 1, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { ciphertext: 1.2, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { ciphertext: 1n, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { ciphertext: Symbol("a"), iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { ciphertext: Buffer, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { ciphertext: Buffer.alloc(1), iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { ciphertext: () => 1, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { ciphertext: {}, iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { ciphertext: [], iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { ciphertext: "", iv: "AxY8DCtDaGlsbGljb3RoZQ" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: undefined },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: null },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: true },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: 1 },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: 1.2 },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: 1n },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: Symbol("a") },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: Buffer },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: Buffer.alloc(1) },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: () => 1 },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: {} },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: [] },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: undefined, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: null, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: true, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: 1, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: 1.2, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: 1n, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: Symbol("a"), tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: Buffer, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: Buffer.alloc(1), tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: () => 1, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: {}, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: [], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: "", tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "pf7CC-iGb8R2ZstoWHErWw", unprotected: undefined },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "pf7CC-iGb8R2ZstoWHErWw", unprotected: null },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "pf7CC-iGb8R2ZstoWHErWw", unprotected: true },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "pf7CC-iGb8R2ZstoWHErWw", unprotected: 1 },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "pf7CC-iGb8R2ZstoWHErWw", unprotected: 1.2 },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "pf7CC-iGb8R2ZstoWHErWw", unprotected: 1n },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "pf7CC-iGb8R2ZstoWHErWw", unprotected: "a" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "pf7CC-iGb8R2ZstoWHErWw", unprotected: Symbol("a") },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "pf7CC-iGb8R2ZstoWHErWw", unprotected: Buffer },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "pf7CC-iGb8R2ZstoWHErWw", unprotected: Buffer.alloc(1) },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "pf7CC-iGb8R2ZstoWHErWw", unprotected: () => 1 },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "pf7CC-iGb8R2ZstoWHErWw", unprotected: {} },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", tag: "pf7CC-iGb8R2ZstoWHErWw", unprotected: [] },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: undefined, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: null, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: true, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: 1, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: 1.2, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: 1n, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: "a", tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: Symbol("a"), tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: Buffer, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: Buffer.alloc(1), tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: () => 1, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: {}, tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [undefined], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [null], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [true], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [1], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [1.2], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [1n], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: ["a"], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [Symbol("a")], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [Buffer], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [Buffer.alloc(1)], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [() => 1], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [[]], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{}], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ header: undefined }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ header: null }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ header: true }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ header: 1 }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ header: 1.2 }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ header: 1n }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ header: "a" }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ header: Symbol("a") }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ header: Buffer }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ header: Buffer.alloc(1) }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ header: () => 1 }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ header: [] }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  {
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [{ encrypted_key: undefined, header: {} }],
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ encrypted_key: null, header: {} }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ encrypted_key: true, header: {} }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ encrypted_key: 1, header: {} }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ encrypted_key: 1.2, header: {} }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ encrypted_key: 1n, header: {} }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  {
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [{ encrypted_key: Symbol("a"), header: {} }],
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ encrypted_key: Buffer, header: {} }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  {
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [{ encrypted_key: Buffer.alloc(1), header: {} }],
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ encrypted_key: () => 1, header: {} }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ encrypted_key: {}, header: {} }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ encrypted_key: [], header: {} }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", recipients: [{ encrypted_key: "", header: {} }], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: "ew", recipients: [{}], tag: "pf7CC-iGb8R2ZstoWHErWw" },
  { iv: "AxY8DCtDaGlsbGljb3RoZQ", protected: "e30", recipients: [{}], tag: "pf7CC-iGb8R2ZstoWHErWw" },
];

const repeatedJoseHeaderParameters: Partial<JsonWebEncryptionHeaderParameters>[][] = [
  [{ alg: "A128KW" }, { alg: "A128KW" }, { enc: "A128CBC-HS256" }],
  [{ alg: "A128KW" }, { enc: "A128CBC-HS256" }, { alg: "A128KW" }],
  [{ enc: "A128CBC-HS256" }, { alg: "A128KW" }, { alg: "A128KW" }],
  [{ alg: "A128KW" }, { alg: "A128KW" }, { alg: "A128KW" }],
];

describe("decode()", () => {
  // #region Uncompressed Attached Token without Additional Authenticated Data
  const uncompressedProtectedAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  };

  const uncompressedUnprotectedAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "wOere2l7R7PoakOvvvxFCg",
    unprotected: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedRecipientAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
      },
    ],
    tag: "wOere2l7R7PoakOvvvxFCg",
  };

  const uncompressedProtectedAndUnprotectedAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedProtectedAndRecipientAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
      },
    ],
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
  };

  const uncompressedUnprotectedAndRecipientAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
      },
    ],
    tag: "wOere2l7R7PoakOvvvxFCg",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const uncompressedFullAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      { encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ", header: { alg: "A128KW", kid: "7" } },
    ],
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Uncompressed Detached Token without Additional Authenticated Data
  const uncompressedProtectedDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  };

  const uncompressedUnprotectedDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "wOere2l7R7PoakOvvvxFCg",
    unprotected: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedRecipientDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
      },
    ],
    tag: "wOere2l7R7PoakOvvvxFCg",
  };

  const uncompressedProtectedAndUnprotectedDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedProtectedAndRecipientDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
      },
    ],
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
  };

  const uncompressedUnprotectedAndRecipientDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
      },
    ],
    tag: "wOere2l7R7PoakOvvvxFCg",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const uncompressedFullDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      { encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ", header: { alg: "A128KW", kid: "7" } },
    ],
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Compressed Attached Token without Additional Authenticated Data
  const compressedProtectedAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "8nmSbluZF1Ws1sABt49r6Q",
  };

  const compressedUnprotectedAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
    unprotected: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
  };

  const compressedRecipientAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: {
          alg: "A128KW",
          enc: "A128CBC-HS256",
          jku: "https://server.example.com/keys.jwks",
          kid: "7",
          zip: "DEF",
        },
      },
    ],
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
  };

  const compressedProtectedAndUnprotectedAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
  };

  const compressedProtectedAndRecipientAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
      },
    ],
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
  };

  const compressedUnprotectedAndRecipientAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
      },
    ],
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const compressedFullAttachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", kid: "7", zip: "DEF" },
      },
    ],
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Compressed Detached Token without Additional Authenticated Data
  const compressedProtectedDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "8nmSbluZF1Ws1sABt49r6Q",
  };

  const compressedUnprotectedDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
    unprotected: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
  };

  const compressedRecipientDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: {
          alg: "A128KW",
          enc: "A128CBC-HS256",
          jku: "https://server.example.com/keys.jwks",
          kid: "7",
          zip: "DEF",
        },
      },
    ],
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
  };

  const compressedProtectedAndUnprotectedDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
  };

  const compressedProtectedAndRecipientDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
      },
    ],
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
  };

  const compressedUnprotectedAndRecipientDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
      },
    ],
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const compressedFullDetachedTokenNoAad: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", kid: "7", zip: "DEF" },
      },
    ],
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Uncompressed Attached Token with Additional Authenticated Data
  const uncompressedProtectedAttachedToken: GeneralJsonWebEncryptionToken = {
    aad:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "2WcnJIVXlq2EYEbHWKr-7g",
  };

  const uncompressedUnprotectedAttachedToken: GeneralJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "W77Q108vf3uFnX_LmZPIlA",
    unprotected: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedRecipientAttachedToken: GeneralJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
      },
    ],
    tag: "W77Q108vf3uFnX_LmZPIlA",
  };

  const uncompressedProtectedAndUnprotectedAttachedToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "ULYMNP5lrIthBrdvAIzyqg",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedProtectedAndRecipientAttachedToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
      },
    ],
    tag: "ULYMNP5lrIthBrdvAIzyqg",
  };

  const uncompressedUnprotectedAndRecipientAttachedToken: GeneralJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
      },
    ],
    tag: "W77Q108vf3uFnX_LmZPIlA",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const uncompressedFullAttachedToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      { encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ", header: { alg: "A128KW", kid: "7" } },
    ],
    tag: "ULYMNP5lrIthBrdvAIzyqg",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Uncompressed Detached Token with Additional Authenticated Data
  const uncompressedProtectedDetachedToken: GeneralJsonWebEncryptionToken = {
    aad:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "2WcnJIVXlq2EYEbHWKr-7g",
  };

  const uncompressedUnprotectedDetachedToken: GeneralJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "W77Q108vf3uFnX_LmZPIlA",
    unprotected: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedRecipientDetachedToken: GeneralJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
      },
    ],
    tag: "W77Q108vf3uFnX_LmZPIlA",
  };

  const uncompressedProtectedAndUnprotectedDetachedToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "ULYMNP5lrIthBrdvAIzyqg",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedProtectedAndRecipientDetachedToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
      },
    ],
    tag: "ULYMNP5lrIthBrdvAIzyqg",
  };

  const uncompressedUnprotectedAndRecipientDetachedToken: GeneralJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
      },
    ],
    tag: "W77Q108vf3uFnX_LmZPIlA",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const uncompressedFullDetachedToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      { encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ", header: { alg: "A128KW", kid: "7" } },
    ],
    tag: "ULYMNP5lrIthBrdvAIzyqg",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Compressed Attached Token with Additional Authenticated Data
  const compressedProtectedAttachedToken: GeneralJsonWebEncryptionToken = {
    aad:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "SRoHlcdRqnsVScLWNZIwtA",
  };

  const compressedUnprotectedAttachedToken: GeneralJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
    unprotected: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
  };

  const compressedRecipientAttachedToken: GeneralJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: {
          alg: "A128KW",
          enc: "A128CBC-HS256",
          jku: "https://server.example.com/keys.jwks",
          kid: "7",
          zip: "DEF",
        },
      },
    ],
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
  };

  const compressedProtectedAndUnprotectedAttachedToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
  };

  const compressedProtectedAndRecipientAttachedToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
      },
    ],
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
  };

  const compressedUnprotectedAndRecipientAttachedToken: GeneralJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
      },
    ],
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const compressedFullAttachedToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", kid: "7", zip: "DEF" },
      },
    ],
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Compressed Detached Token with Additional Authenticated Data
  const compressedProtectedDetachedToken: GeneralJsonWebEncryptionToken = {
    aad:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "SRoHlcdRqnsVScLWNZIwtA",
  };

  const compressedUnprotectedDetachedToken: GeneralJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
    unprotected: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
  };

  const compressedRecipientDetachedToken: GeneralJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: {
          alg: "A128KW",
          enc: "A128CBC-HS256",
          jku: "https://server.example.com/keys.jwks",
          kid: "7",
          zip: "DEF",
        },
      },
    ],
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
  };

  const compressedProtectedAndUnprotectedDetachedToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
  };

  const compressedProtectedAndRecipientDetachedToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
      },
    ],
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
  };

  const compressedUnprotectedAndRecipientDetachedToken: GeneralJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
      },
    ],
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const compressedFullDetachedToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      {
        encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
        header: { alg: "A128KW", kid: "7", zip: "DEF" },
      },
    ],
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion

  const encHeader: Partial<JsonWebEncryptionHeaderParameters> = { enc: "A128CBC-HS256" };
  const jkuHeader: Partial<JsonWebEncryptionHeaderParameters> = { jku: "https://server.example.com/keys.jwks" };
  const algKidHeader: Partial<JsonWebEncryptionHeaderParameters> = { alg: "A128KW", kid: "7" };

  const algZipKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: "A128KW",
    kid: "7",
    zip: "DEF",
  };

  const algJkuKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: "A128KW",
    jku: "https://server.example.com/keys.jwks",
    kid: "7",
  };

  const algEncJkuKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: "A128KW",
    enc: "A128CBC-HS256",
    jku: "https://server.example.com/keys.jwks",
    kid: "7",
  };

  const algZipJkuKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: "A128KW",
    jku: "https://server.example.com/keys.jwks",
    kid: "7",
    zip: "DEF",
  };

  const algEncZipJkuKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: "A128KW",
    enc: "A128CBC-HS256",
    jku: "https://server.example.com/keys.jwks",
    kid: "7",
    zip: "DEF",
  };

  const encryptedKey = Buffer.from("6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ", "base64url");
  const initializationVector = Buffer.from("AxY8DCtDaGlsbGljb3RoZQ", "base64url");
  const ciphertext = Buffer.from("KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY", "base64url");
  const compressedCiphertext = Buffer.from("7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA", "base64url");
  const additionalAuthenticatedData = Buffer.from("YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE", "base64url");

  const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
    k: "GawgguFyGrWKav7AX4VKUg",
    kid: "7",
    kty: "oct",
  });

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);

    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ keys: [jsonWebKey.parameters] }),
    } as Response);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetAllMocks();
  });

  it.each(invalidTokens)(
    "should throw when the provided General JSON Web Encryption Token is invalid.",
    async (token) => {
      const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
      await expect(decode(token)).rejects.toThrow(error);
    },
  );

  it.each(invalidTokenFormats)(
    "should throw when the provided General JSON Web Encryption Token has an invalid format.",
    async (token) => {
      const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
      await expect(decode(token)).rejects.toThrow(error);
    },
  );

  it.each(repeatedJoseHeaderParameters)(
    "should throw when there are repeated JSON Web Encryption Header Parameters.",
    async (protectedHeader, unprotectedHeader, recipientUnprotectedHeader) => {
      const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

      await expect(
        decode({
          ...uncompressedFullAttachedTokenNoAad,
          protected: Buffer.from(JSON.stringify(protectedHeader), "utf8").toString("base64url"),
          recipients: [
            {
              encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
              header: recipientUnprotectedHeader,
            },
          ],
          unprotected: unprotectedHeader,
        }),
      ).rejects.toThrow(error);
    },
  );

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("pf7CC-iGb8R2ZstoWHErWw", "base64url"),
      ciphertext,
      initializationVector,
      protectedHeader: algEncJkuKidHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("wOere2l7R7PoakOvvvxFCg", "base64url"),
      ciphertext,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("wOere2l7R7PoakOvvvxFCg", "base64url"),
      ciphertext,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("Mz-VPPyU4RlcuYv1IwIvzw", "base64url"),
      ciphertext,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("Mz-VPPyU4RlcuYv1IwIvzw", "base64url"),
      ciphertext,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("wOere2l7R7PoakOvvvxFCg", "base64url"),
      ciphertext,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(decode(uncompressedFullAttachedTokenNoAad)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData: null,
        authenticationTag: Buffer.from("Mz-VPPyU4RlcuYv1IwIvzw", "base64url"),
        ciphertext,
        initializationVector,
        protectedHeader: encHeader,
        recipients: [
          {
            encryptedKey,
            header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
            recipientUnprotectedHeader: algKidHeader,
          },
        ],
        unprotectedHeader: jkuHeader,
      },
    );
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("pf7CC-iGb8R2ZstoWHErWw", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: algEncJkuKidHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("wOere2l7R7PoakOvvvxFCg", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("wOere2l7R7PoakOvvvxFCg", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("Mz-VPPyU4RlcuYv1IwIvzw", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("Mz-VPPyU4RlcuYv1IwIvzw", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("wOere2l7R7PoakOvvvxFCg", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(decode(uncompressedFullDetachedTokenNoAad)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData: null,
        authenticationTag: Buffer.from("Mz-VPPyU4RlcuYv1IwIvzw", "base64url"),
        ciphertext: null,
        initializationVector,
        protectedHeader: encHeader,
        recipients: [
          {
            encryptedKey,
            header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
            recipientUnprotectedHeader: algKidHeader,
          },
        ],
        unprotectedHeader: jkuHeader,
      },
    );
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("8nmSbluZF1Ws1sABt49r6Q", "base64url"),
      ciphertext: compressedCiphertext,
      initializationVector,
      protectedHeader: algEncZipJkuKidHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("6mQsBNyxIUzsP37fC54ZjQ", "base64url"),
      ciphertext: compressedCiphertext,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("6mQsBNyxIUzsP37fC54ZjQ", "base64url"),
      ciphertext: compressedCiphertext,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected and Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("FVFsNAUL3jgdAmZnSVxAFQ", "base64url"),
      ciphertext: compressedCiphertext,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("FVFsNAUL3jgdAmZnSVxAFQ", "base64url"),
      ciphertext: compressedCiphertext,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("6mQsBNyxIUzsP37fC54ZjQ", "base64url"),
      ciphertext: compressedCiphertext,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(decode(compressedFullAttachedTokenNoAad)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("FVFsNAUL3jgdAmZnSVxAFQ", "base64url"),
      ciphertext: compressedCiphertext,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("8nmSbluZF1Ws1sABt49r6Q", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: algEncZipJkuKidHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("6mQsBNyxIUzsP37fC54ZjQ", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("6mQsBNyxIUzsP37fC54ZjQ", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected and Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("FVFsNAUL3jgdAmZnSVxAFQ", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("FVFsNAUL3jgdAmZnSVxAFQ", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("6mQsBNyxIUzsP37fC54ZjQ", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(decode(compressedFullDetachedTokenNoAad)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("FVFsNAUL3jgdAmZnSVxAFQ", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected Attached Token with Additional Authenticated Data.", async () => {
    await expect(decode(uncompressedProtectedAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData,
        authenticationTag: Buffer.from("2WcnJIVXlq2EYEbHWKr-7g", "base64url"),
        ciphertext,
        initializationVector,
        protectedHeader: algEncJkuKidHeader,
        recipients: [
          {
            encryptedKey,
            header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
            recipientUnprotectedHeader: null,
          },
        ],
        unprotectedHeader: null,
      },
    );
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("W77Q108vf3uFnX_LmZPIlA", "base64url"),
      ciphertext,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(decode(uncompressedRecipientAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData,
        authenticationTag: Buffer.from("W77Q108vf3uFnX_LmZPIlA", "base64url"),
        ciphertext,
        initializationVector,
        protectedHeader: null,
        recipients: [
          {
            encryptedKey,
            header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
            recipientUnprotectedHeader: algEncJkuKidHeader,
          },
        ],
        unprotectedHeader: null,
      },
    );
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("ULYMNP5lrIthBrdvAIzyqg", "base64url"),
      ciphertext,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("ULYMNP5lrIthBrdvAIzyqg", "base64url"),
      ciphertext,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("W77Q108vf3uFnX_LmZPIlA", "base64url"),
      ciphertext,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(decode(uncompressedFullAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("ULYMNP5lrIthBrdvAIzyqg", "base64url"),
      ciphertext,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected Detached Token with Additional Authenticated Data.", async () => {
    await expect(decode(uncompressedProtectedDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData,
        authenticationTag: Buffer.from("2WcnJIVXlq2EYEbHWKr-7g", "base64url"),
        ciphertext: null,
        initializationVector,
        protectedHeader: algEncJkuKidHeader,
        recipients: [
          {
            encryptedKey,
            header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
            recipientUnprotectedHeader: null,
          },
        ],
        unprotectedHeader: null,
      },
    );
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("W77Q108vf3uFnX_LmZPIlA", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(decode(uncompressedRecipientDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData,
        authenticationTag: Buffer.from("W77Q108vf3uFnX_LmZPIlA", "base64url"),
        ciphertext: null,
        initializationVector,
        protectedHeader: null,
        recipients: [
          {
            encryptedKey,
            header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
            recipientUnprotectedHeader: algEncJkuKidHeader,
          },
        ],
        unprotectedHeader: null,
      },
    );
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("ULYMNP5lrIthBrdvAIzyqg", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("ULYMNP5lrIthBrdvAIzyqg", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("W77Q108vf3uFnX_LmZPIlA", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(decode(uncompressedFullDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("ULYMNP5lrIthBrdvAIzyqg", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected Attached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedProtectedAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("SRoHlcdRqnsVScLWNZIwtA", "base64url"),
      ciphertext: compressedCiphertext,
      initializationVector,
      protectedHeader: algEncZipJkuKidHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedUnprotectedAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData,
        authenticationTag: Buffer.from("0Z9lyKxM6Rz-6zCUcfNOmQ", "base64url"),
        ciphertext: compressedCiphertext,
        initializationVector,
        protectedHeader: null,
        recipients: [
          {
            encryptedKey,
            header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
            recipientUnprotectedHeader: null,
          },
        ],
        unprotectedHeader: algEncZipJkuKidHeader,
      },
    );
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedRecipientAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("0Z9lyKxM6Rz-6zCUcfNOmQ", "base64url"),
      ciphertext: compressedCiphertext,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected and Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("1IIFfjlJQ4EkqwKhBdlY5w", "base64url"),
      ciphertext: compressedCiphertext,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("1IIFfjlJQ4EkqwKhBdlY5w", "base64url"),
      ciphertext: compressedCiphertext,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("0Z9lyKxM6Rz-6zCUcfNOmQ", "base64url"),
      ciphertext: compressedCiphertext,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedFullAttachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("1IIFfjlJQ4EkqwKhBdlY5w", "base64url"),
      ciphertext: compressedCiphertext,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected Detached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedProtectedDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("SRoHlcdRqnsVScLWNZIwtA", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: algEncZipJkuKidHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedUnprotectedDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData,
        authenticationTag: Buffer.from("0Z9lyKxM6Rz-6zCUcfNOmQ", "base64url"),
        ciphertext: null,
        initializationVector,
        protectedHeader: null,
        recipients: [
          {
            encryptedKey,
            header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
            recipientUnprotectedHeader: null,
          },
        ],
        unprotectedHeader: algEncZipJkuKidHeader,
      },
    );
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedRecipientDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("0Z9lyKxM6Rz-6zCUcfNOmQ", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected and Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("1IIFfjlJQ4EkqwKhBdlY5w", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("1IIFfjlJQ4EkqwKhBdlY5w", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("0Z9lyKxM6Rz-6zCUcfNOmQ", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: null,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the General JSON Web Encryption Parameters from a Compressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedFullDetachedToken)).resolves.toStrictEqual<GeneralJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("1IIFfjlJQ4EkqwKhBdlY5w", "base64url"),
      ciphertext: null,
      initializationVector,
      protectedHeader: encHeader,
      recipients: [
        {
          encryptedKey,
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });
});
