import { Buffer } from "node:buffer";
import * as crypto from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidJoseHeaderError } from "../../../../errors/invalid-jose-header.error.ts";
import type { KeyManagementAlgorithm } from "../../../../jwa/jwe/alg/key-management-algorithm.type.ts";
import { AESCBCContentEncryptionBackend } from "../../../../jwa/jwe/enc/aescbc/aescbc.content-encryption.backend.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import type { GeneralJsonWebEncryptionToken } from "../general.jsonwebencryption.token.ts";
import { serialize } from "./serialize.ts";

vi.mock(import("node:crypto"), async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, randomBytes: vi.fn() };
});

const fetchMock = vi.fn<typeof globalThis.fetch>();

const invalidPlaintexts: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  () => 1,
  {},
  [],
  Buffer.alloc(0),
];

const invalidProtectedHeaders: any[] = [
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

const invalidUnprotectedHeaders: any[] = [
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

const invalidRecipients: any[] = [
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

const invalidRecipientUnprotectedHeaders: any[] = [
  [[{ recipientUnprotectedHeader: undefined }]],
  [[{ recipientUnprotectedHeader: null }]],
  [[{ recipientUnprotectedHeader: true }]],
  [[{ recipientUnprotectedHeader: 1 }]],
  [[{ recipientUnprotectedHeader: 1.2 }]],
  [[{ recipientUnprotectedHeader: 1n }]],
  [[{ recipientUnprotectedHeader: "a" }]],
  [[{ recipientUnprotectedHeader: Symbol("a") }]],
  [[{ recipientUnprotectedHeader: Buffer }]],
  [[{ recipientUnprotectedHeader: Buffer.alloc(1) }]],
  [[{ recipientUnprotectedHeader: () => 1 }]],
  [[{ recipientUnprotectedHeader: [] }]],
];

const repeatedJoseHeaderParameters: Partial<JsonWebEncryptionHeaderParameters>[][] = [
  [{ alg: "A128KW" }, { alg: "A128KW" }, { enc: "A128CBC-HS256" }],
  [{ alg: "A128KW" }, { enc: "A128CBC-HS256" }, { alg: "A128KW" }],
  [{ enc: "A128CBC-HS256" }, { alg: "A128KW" }, { alg: "A128KW" }],
  [{ alg: "A128KW" }, { alg: "A128KW" }, { alg: "A128KW" }],
];

const forbiddenKeyManagementAlgorithms: KeyManagementAlgorithm[] = ["ECDH-ES", "dir"];

const invalidSerializeOptions: any[] = [null, true, 1, 1.2, 1n, "a", Symbol("a"), Buffer, Buffer.alloc(1), () => 1, []];

const invalidAdditionalAuthenticatedData: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  () => 1,
  {},
  [],
  Buffer.alloc(0),
];

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
  [undefined],
  [true],
  [1],
  [1.2],
  [1n],
  ["a"],
  [Symbol("a")],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [{}],
  [[]],
  [
    new JsonWebKey<OctetSequenceJsonWebKeyParameters>({ k: "0123456789abcdef", kty: "oct" }),
    new JsonWebKey<OctetSequenceJsonWebKeyParameters>({ k: "0123456789abcdef", kty: "oct" }),
  ],
];

const invalidDetacheds: any[] = [
  undefined,
  null,
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

describe("serialize()", () => {
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
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "D2-UZ55aSvHABpCQuVbnpw",
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
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "D2-UZ55aSvHABpCQuVbnpw",
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
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "S-xriw1TDdCen7cg2qn1Gg",
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
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9",
    recipients: [{ encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ" }],
    tag: "S-xriw1TDdCen7cg2qn1Gg",
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

  const plaintext = Buffer.from("Live long and prosper.");

  const encHeader: Partial<JsonWebEncryptionHeaderParameters> = { enc: "A128CBC-HS256" };
  const jkuHeader: Partial<JsonWebEncryptionHeaderParameters> = { jku: "https://server.example.com/keys.jwks" };
  const algEncKidHeader: Partial<JsonWebEncryptionHeaderParameters> = { alg: "A128KW", enc: "A128CBC-HS256", kid: "7" };
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

  const initializationVector = Buffer.from("AxY8DCtDaGlsbGljb3RoZQ", "base64url");
  const additionalAuthenticatedData = Buffer.from("YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE", "base64url");

  const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
    k: "GawgguFyGrWKav7AX4VKUg",
    kid: "7",
    kty: "oct",
  });

  beforeEach(() => {
    vi.mocked(crypto.randomBytes).mockImplementation((_, cb) =>
      cb(null, Buffer.from("BNMfxVSd_P4LZJ36P6pqzmt81C1vawnbyLEA8I-cLM8", "base64url")),
    );

    vi.stubGlobal("fetch", fetchMock);

    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ keys: [jsonWebKey.parameters] }),
    } as Response);

    vi.spyOn(AESCBCContentEncryptionBackend.prototype, "generateInitializationVector").mockResolvedValueOnce(
      initializationVector,
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetAllMocks();
    vi.restoreAllMocks();
  });

  it.each(invalidPlaintexts)("should throw when the provided Plaintext is invalid.", async (payload) => {
    const error = new TypeError("The provided Plaintext is invalid.");

    await expect(
      serialize(payload, {
        protectedHeader: encHeader,
        recipients: [{ recipientUnprotectedHeader: algKidHeader }],
        unprotectedHeader: jkuHeader,
      }),
    ).rejects.toThrow(error);
  });

  it.each(invalidProtectedHeaders)(
    "should throw when the provided JSON Web Encryption Protected Header is invalid.",
    async (protectedHeader) => {
      const error = new TypeError("The provided JSON Web Encryption Protected Header is invalid.");
      await expect(
        serialize(plaintext, {
          protectedHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
          unprotectedHeader: jkuHeader,
        }),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidUnprotectedHeaders)(
    "should throw when the provided JSON Web Encryption Unprotected Header is invalid.",
    async (unprotectedHeader) => {
      const error = new TypeError("The provided JSON Web Encryption Unprotected Header is invalid.");

      await expect(
        serialize(plaintext, {
          protectedHeader: encHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
          unprotectedHeader,
        }),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidRecipients)(
    "should throw when the provided JSON Web Encryption Recipients is invalid.",
    async (recipients) => {
      const error = new TypeError("The provided JSON Web Encryption Recipients is invalid.");

      await expect(
        serialize(plaintext, { protectedHeader: encHeader, recipients, unprotectedHeader: jkuHeader }),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidRecipientUnprotectedHeaders)(
    "should throw when the provided JSON Web Encryption Recipient Unprotected Header is invalid.",
    async (recipientUnprotectedHeader) => {
      const error = new TypeError("The provided JSON Web Encryption Recipient Unprotected Header is invalid.");

      await expect(
        serialize(plaintext, {
          protectedHeader: encHeader,
          recipients: [{ recipientUnprotectedHeader }],
          unprotectedHeader: jkuHeader,
        }),
      ).rejects.toThrow(error);
    },
  );

  it("should throw when no JSON Web Encryption Header is provided.", async () => {
    const error = new TypeError("Missing at least one required JSON Web Encryption Header.");
    await expect(serialize(plaintext, { recipients: [{}] })).rejects.toThrow(error);
  });

  it.each(repeatedJoseHeaderParameters)(
    "should throw when there are repeated JSON Web Encryption Header Parameters.",
    async (protectedHeader, unprotectedHeader, recipientUnprotectedHeader) => {
      const error = new TypeError("Cannot have repeated JSON Web Encryption Header Parameters.");

      await expect(
        serialize(plaintext, { protectedHeader, recipients: [{ recipientUnprotectedHeader }], unprotectedHeader }),
      ).rejects.toThrow(error);
    },
  );

  it.each(forbiddenKeyManagementAlgorithms)(
    "should throw when providing a forbidden Key Management Algorithm.",
    async (alg) => {
      const error = new InvalidJoseHeaderError(
        'Cannot use the Key Management Algorithms "ECDH-ES" and "dir" with General JSON Web Encryption Serializations.',
      );

      await expect(
        serialize(plaintext, {
          protectedHeader: encHeader,
          recipients: [{ recipientUnprotectedHeader: { ...algKidHeader, alg } }],
          unprotectedHeader: jkuHeader,
        }),
      ).rejects.toThrow(error);
    },
  );

  it("should throw when providing more than one Content Encryption Algorithms.", async () => {
    const error = new InvalidJoseHeaderError("Cannot have distinct Content Encryption Algorithms.");

    await expect(
      serialize(plaintext, {
        protectedHeader: algKidHeader,
        recipients: [
          { recipientUnprotectedHeader: { enc: "A128CBC-HS256" } },
          { recipientUnprotectedHeader: { enc: "A128GCM" } },
        ],
        unprotectedHeader: jkuHeader,
      }),
    ).rejects.toThrow(error);
  });

  it("should throw when providing more than one Compression Algorithms.", async () => {
    const error = new InvalidJoseHeaderError("Cannot have distinct Compression Algorithms.");

    await expect(
      serialize(plaintext, {
        protectedHeader: algEncKidHeader,
        recipients: [{ recipientUnprotectedHeader: {} }, { recipientUnprotectedHeader: { zip: "DEF" } }],
        unprotectedHeader: jkuHeader,
      }),
    ).rejects.toThrow(error);
  });

  it.each(invalidSerializeOptions)(
    "should throw when the provided General JSON Web Encryption Serialize Options is invalid.",
    async (options) => {
      const error = new TypeError("The provided General JSON Web Encryption Serialize Options is invalid.");

      await expect(
        serialize(
          plaintext,
          {
            protectedHeader: encHeader,
            recipients: [{ recipientUnprotectedHeader: algKidHeader }],
            unprotectedHeader: jkuHeader,
          },
          options,
        ),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidAdditionalAuthenticatedData)(
    'should throw when the provided General JSON Web Encryption Serialize Option "additionalAuthenticatedData" is invalid.',
    async (_additionalAuthenticatedData) => {
      const error = new TypeError(
        'The provided General JSON Web Encryption Serialize Option "additionalAuthenticatedData" is invalid.',
      );

      await expect(
        serialize(
          plaintext,
          {
            protectedHeader: encHeader,
            recipients: [{ recipientUnprotectedHeader: algKidHeader }],
            unprotectedHeader: jkuHeader,
          },
          { additionalAuthenticatedData: _additionalAuthenticatedData },
        ),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidJsonWebKeys)(
    'should throw when the provided General JSON Web Encryption Serialize Option "jsonWebKeys" is invalid.',
    async (jsonWebKeys) => {
      const error = new TypeError(
        'The provided General JSON Web Encryption Serialize Option "jsonWebKeys" is invalid.',
      );

      await expect(
        serialize(
          plaintext,
          {
            protectedHeader: encHeader,
            recipients: [{ recipientUnprotectedHeader: algKidHeader }],
            unprotectedHeader: jkuHeader,
          },
          { jsonWebKeys },
        ),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidDetacheds)(
    'should throw when the provided General JSON Web Encryption Serialize Option "detached" is invalid.',
    async (detached) => {
      const error = new TypeError('The provided General JSON Web Encryption Serialize Option "detached" is invalid.');

      await expect(
        serialize(
          plaintext,
          {
            protectedHeader: encHeader,
            recipients: [{ recipientUnprotectedHeader: algKidHeader }],
            unprotectedHeader: jkuHeader,
          },
          { detached },
        ),
      ).rejects.toThrow(error);
    },
  );

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncJkuKidHeader, recipients: [{}] }),
    ).resolves.toStrictEqual(uncompressedProtectedAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { recipients: [{}], unprotectedHeader: algEncJkuKidHeader }, { jsonWebKeys: [jsonWebKey] }),
    ).resolves.toStrictEqual(uncompressedUnprotectedAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncJkuKidHeader }] },
        { jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedRecipientAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected and Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{}], unprotectedHeader: algJkuKidHeader },
        { jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }] },
        { jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }], unprotectedHeader: encHeader },
        { jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
          unprotectedHeader: jkuHeader,
        },
        { jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedFullAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncJkuKidHeader, recipients: [{}] },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{}], unprotectedHeader: algEncJkuKidHeader },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncJkuKidHeader }] },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedRecipientDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected and Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{}], unprotectedHeader: algJkuKidHeader },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }] },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }], unprotectedHeader: encHeader },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
          unprotectedHeader: jkuHeader,
        },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedFullDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncZipJkuKidHeader, recipients: [{}] }, { jsonWebKeys: [jsonWebKey] }),
    ).resolves.toStrictEqual(compressedProtectedAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{}], unprotectedHeader: algEncZipJkuKidHeader },
        { jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncZipJkuKidHeader }] },
        { jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedRecipientAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected and Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{}], unprotectedHeader: algZipJkuKidHeader },
        { jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }] },
        { jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }], unprotectedHeader: encHeader },
        { jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          recipients: [{ recipientUnprotectedHeader: algZipKidHeader }],
          unprotectedHeader: jkuHeader,
        },
        { jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedFullAttachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncZipJkuKidHeader, recipients: [{}] },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedProtectedDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{}], unprotectedHeader: algEncZipJkuKidHeader },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncZipJkuKidHeader }] },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedRecipientDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected and Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{}], unprotectedHeader: algZipJkuKidHeader },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }] },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }], unprotectedHeader: encHeader },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          recipients: [{ recipientUnprotectedHeader: algZipKidHeader }],
          unprotectedHeader: jkuHeader,
        },
        { detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedFullDetachedTokenNoAad);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncJkuKidHeader, recipients: [{}] },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{}], unprotectedHeader: algEncJkuKidHeader },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncJkuKidHeader }] },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedRecipientAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected and Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{}], unprotectedHeader: algJkuKidHeader },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }] },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }], unprotectedHeader: encHeader },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
          unprotectedHeader: jkuHeader,
        },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedFullAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncJkuKidHeader, recipients: [{}] },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedDetachedToken);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{}], unprotectedHeader: algEncJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedDetachedToken);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncJkuKidHeader }] },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedRecipientDetachedToken);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected and Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{}], unprotectedHeader: algJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedDetachedToken);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }] },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientDetachedToken);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algJkuKidHeader }], unprotectedHeader: encHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientDetachedToken);
  });

  it("should serialize a General JSON Web Encryption into an Uncompressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          recipients: [{ recipientUnprotectedHeader: algKidHeader }],
          unprotectedHeader: jkuHeader,
        },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(uncompressedFullDetachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncZipJkuKidHeader, recipients: [{}] },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{}], unprotectedHeader: algEncZipJkuKidHeader },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncZipJkuKidHeader }] },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedRecipientAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected and Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{}], unprotectedHeader: algZipJkuKidHeader },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }] },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }], unprotectedHeader: encHeader },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          recipients: [{ recipientUnprotectedHeader: algZipKidHeader }],
          unprotectedHeader: jkuHeader,
        },
        { additionalAuthenticatedData, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedFullAttachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncZipJkuKidHeader, recipients: [{}] },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedProtectedDetachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{}], unprotectedHeader: algEncZipJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedDetachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algEncZipJkuKidHeader }] },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedRecipientDetachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected and Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{}], unprotectedHeader: algZipJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedDetachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }] },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientDetachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipients: [{ recipientUnprotectedHeader: algZipJkuKidHeader }], unprotectedHeader: encHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientDetachedToken);
  });

  it("should serialize a General JSON Web Encryption into an compressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        {
          protectedHeader: encHeader,
          recipients: [{ recipientUnprotectedHeader: algZipKidHeader }],
          unprotectedHeader: jkuHeader,
        },
        { additionalAuthenticatedData, detached: true, jsonWebKeys: [jsonWebKey] },
      ),
    ).resolves.toStrictEqual(compressedFullDetachedToken);
  });
});
