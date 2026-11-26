import { Buffer } from "node:buffer";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AESKWKeyManagementBackend } from "../../../../jwa/jwe/alg/aeskw/aeskw.key-management.backend.ts";
import { AESCBCContentEncryptionBackend } from "../../../../jwa/jwe/enc/aescbc/aescbc.content-encryption.backend.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import type { FlattenedJsonWebEncryptionToken } from "../flattened.jsonwebencryption.token.ts";
import { serialize } from "./serialize.ts";

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

const invalidHeaders: any[] = [
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

const invalidRecipientUnprotectedHeaders: any[] = [
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

const repeatedJoseHeaderParameters: Partial<JsonWebEncryptionHeaderParameters>[][] = [
  [{ alg: "A128KW" }, { alg: "A128KW" }, { enc: "A128CBC-HS256" }],
  [{ alg: "A128KW" }, { enc: "A128CBC-HS256" }, { alg: "A128KW" }],
  [{ enc: "A128CBC-HS256" }, { alg: "A128KW" }, { alg: "A128KW" }],
  [{ alg: "A128KW" }, { alg: "A128KW" }, { alg: "A128KW" }],
];

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
  const uncompressedProtectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  };

  const uncompressedUnprotectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "wOere2l7R7PoakOvvvxFCg",
    unprotected: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "wOere2l7R7PoakOvvvxFCg",
  };

  const uncompressedProtectedAndUnprotectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedProtectedAndRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
  };

  const uncompressedUnprotectedAndRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "wOere2l7R7PoakOvvvxFCg",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const uncompressedFullAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Uncompressed Detached Token without Additional Authenticated Data
  const uncompressedProtectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  };

  const uncompressedUnprotectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "wOere2l7R7PoakOvvvxFCg",
    unprotected: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "wOere2l7R7PoakOvvvxFCg",
  };

  const uncompressedProtectedAndUnprotectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedProtectedAndRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
  };

  const uncompressedUnprotectedAndRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "wOere2l7R7PoakOvvvxFCg",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const uncompressedFullDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Compressed Attached Token without Additional Authenticated Data
  const compressedProtectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9",
    tag: "D2-UZ55aSvHABpCQuVbnpw",
  };

  const compressedUnprotectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
    unprotected: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
  };

  const compressedRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
  };

  const compressedProtectedAndUnprotectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
  };

  const compressedProtectedAndRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
  };

  const compressedUnprotectedAndRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const compressedFullAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Compressed Detached Token without Additional Authenticated Data
  const compressedProtectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9",
    tag: "D2-UZ55aSvHABpCQuVbnpw",
  };

  const compressedUnprotectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
    unprotected: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
  };

  const compressedRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
  };

  const compressedProtectedAndUnprotectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
  };

  const compressedProtectedAndRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
  };

  const compressedUnprotectedAndRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const compressedFullDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Uncompressed Attached Token with Additional Authenticated Data
  const uncompressedProtectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "2WcnJIVXlq2EYEbHWKr-7g",
  };

  const uncompressedUnprotectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "W77Q108vf3uFnX_LmZPIlA",
    unprotected: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "W77Q108vf3uFnX_LmZPIlA",
  };

  const uncompressedProtectedAndUnprotectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "ULYMNP5lrIthBrdvAIzyqg",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedProtectedAndRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "ULYMNP5lrIthBrdvAIzyqg",
  };

  const uncompressedUnprotectedAndRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "W77Q108vf3uFnX_LmZPIlA",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const uncompressedFullAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "ULYMNP5lrIthBrdvAIzyqg",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Uncompressed Detached Token with Additional Authenticated Data
  const uncompressedProtectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "2WcnJIVXlq2EYEbHWKr-7g",
  };

  const uncompressedUnprotectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "W77Q108vf3uFnX_LmZPIlA",
    unprotected: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "W77Q108vf3uFnX_LmZPIlA",
  };

  const uncompressedProtectedAndUnprotectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "ULYMNP5lrIthBrdvAIzyqg",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedProtectedAndRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "ULYMNP5lrIthBrdvAIzyqg",
  };

  const uncompressedUnprotectedAndRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "W77Q108vf3uFnX_LmZPIlA",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const uncompressedFullDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "ULYMNP5lrIthBrdvAIzyqg",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Compressed Attached Token with Additional Authenticated Data
  const compressedProtectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9",
    tag: "S-xriw1TDdCen7cg2qn1Gg",
  };

  const compressedUnprotectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
    unprotected: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
  };

  const compressedRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
  };

  const compressedProtectedAndUnprotectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
  };

  const compressedProtectedAndRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
  };

  const compressedUnprotectedAndRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const compressedFullAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Compressed Detached Token with Additional Authenticated Data
  const compressedProtectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyIsInppcCI6IkRFRiJ9",
    tag: "S-xriw1TDdCen7cg2qn1Gg",
  };

  const compressedUnprotectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
    unprotected: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
  };

  const compressedRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
  };

  const compressedProtectedAndUnprotectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
  };

  const compressedProtectedAndRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
  };

  const compressedUnprotectedAndRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const compressedFullDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion

  const plaintext = Buffer.from("Live long and prosper.");

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

  const contentEncryptionKey = Buffer.from("BNMfxVSd_P4LZJ36P6pqzmt81C1vawnbyLEA8I-cLM8", "base64url");
  const initializationVector = Buffer.from("AxY8DCtDaGlsbGljb3RoZQ", "base64url");
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

    vi.spyOn(AESKWKeyManagementBackend.prototype, "generateContentEncryptionKey").mockResolvedValueOnce(
      contentEncryptionKey,
    );

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
        recipientUnprotectedHeader: algKidHeader,
        unprotectedHeader: jkuHeader,
      }),
    ).rejects.toThrow(error);
  });

  it.each(invalidHeaders)("should throw when the provided JSON Web Encryption Headers is invalid.", async (headers) => {
    const error = new TypeError("The provided JSON Web Encryption Headers is invalid.");
    await expect(serialize(plaintext, headers)).rejects.toThrow(error);
  });

  it.each(invalidProtectedHeaders)(
    "should throw when the provided JSON Web Encryption Protected Header is invalid.",
    async (protectedHeader) => {
      const error = new TypeError("The provided JSON Web Encryption Protected Header is invalid.");
      await expect(
        serialize(plaintext, {
          protectedHeader,
          recipientUnprotectedHeader: algKidHeader,
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
          recipientUnprotectedHeader: algKidHeader,
          unprotectedHeader,
        }),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidRecipientUnprotectedHeaders)(
    "should throw when the provided JSON Web Encryption Recipient Unprotected Header is invalid.",
    async (recipientUnprotectedHeader) => {
      const error = new TypeError("The provided JSON Web Encryption Recipient Unprotected Header is invalid.");

      await expect(
        serialize(plaintext, { protectedHeader: encHeader, recipientUnprotectedHeader, unprotectedHeader: jkuHeader }),
      ).rejects.toThrow(error);
    },
  );

  it("should throw when no JSON Web Encryption Header is provided.", async () => {
    const error = new TypeError("Missing at least one required JSON Web Encryption Header.");
    await expect(serialize(plaintext, {})).rejects.toThrow(error);
  });

  it.each(repeatedJoseHeaderParameters)(
    "should throw when there are repeated JSON Web Encryption Header Parameters.",
    async (protectedHeader, unprotectedHeader, recipientUnprotectedHeader) => {
      const error = new TypeError("Cannot have repeated JSON Web Encryption Header Parameters.");

      await expect(
        serialize(plaintext, { protectedHeader, recipientUnprotectedHeader, unprotectedHeader }),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidSerializeOptions)(
    "should throw when the provided Flattened JSON Web Encryption Serialize Options is invalid.",
    async (options) => {
      const error = new TypeError("The provided Flattened JSON Web Encryption Serialize Options is invalid.");

      await expect(
        serialize(
          plaintext,
          { protectedHeader: encHeader, recipientUnprotectedHeader: algKidHeader, unprotectedHeader: jkuHeader },
          options,
        ),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidAdditionalAuthenticatedData)(
    'should throw when the provided option "additionalAuthenticatedData" is invalid.',
    async (_additionalAuthenticatedData) => {
      const error = new TypeError(
        'The provided Flattened JSON Web Encryption Serialize Option "additionalAuthenticatedData" is invalid.',
      );

      await expect(
        serialize(
          plaintext,
          { protectedHeader: encHeader, recipientUnprotectedHeader: algKidHeader, unprotectedHeader: jkuHeader },
          { additionalAuthenticatedData: _additionalAuthenticatedData },
        ),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidJsonWebKeys)(
    'should throw when the provided Flattened JSON Web Encryption Serialize Option "jsonWebKey" is invalid.',
    async (_jsonWebKey) => {
      const error = new TypeError(
        'The provided Flattened JSON Web Encryption Serialize Option "jsonWebKey" is invalid.',
      );

      await expect(
        serialize(
          plaintext,
          { protectedHeader: encHeader, recipientUnprotectedHeader: algKidHeader, unprotectedHeader: jkuHeader },
          { jsonWebKey: _jsonWebKey },
        ),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidDetacheds)(
    'should throw when the provided Flattened JSON Web Encryption Serialize Option "detached" is invalid.',
    async (detached) => {
      const error = new TypeError('The provided Flattened JSON Web Encryption Serialize Option "detached" is invalid.');

      await expect(
        serialize(
          plaintext,
          { protectedHeader: encHeader, recipientUnprotectedHeader: algKidHeader, unprotectedHeader: jkuHeader },
          { detached },
        ),
      ).rejects.toThrow(error);
    },
  );

  it("should serialize a Flattened JSON Web Encryption Uncompressed Protected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(serialize(plaintext, { protectedHeader: algEncJkuKidHeader })).resolves.toStrictEqual(
      uncompressedProtectedAttachedTokenNoAad,
    );
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: algEncJkuKidHeader }, { jsonWebKey }),
    ).resolves.toStrictEqual(uncompressedUnprotectedAttachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Recipient Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { recipientUnprotectedHeader: algEncJkuKidHeader }, { jsonWebKey }),
    ).resolves.toStrictEqual(uncompressedRecipientAttachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Protected and Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { protectedHeader: encHeader, unprotectedHeader: algJkuKidHeader }, { jsonWebKey }),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedAttachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Protected and Recipient Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { protectedHeader: encHeader, recipientUnprotectedHeader: algJkuKidHeader }, { jsonWebKey }),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientAttachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Unprotected and Recipient Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algJkuKidHeader, unprotectedHeader: encHeader },
        { jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientAttachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Full Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algKidHeader, unprotectedHeader: jkuHeader },
        { jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedFullAttachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Protected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncJkuKidHeader }, { detached: true, jsonWebKey }),
    ).resolves.toStrictEqual(uncompressedProtectedDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: algEncJkuKidHeader }, { detached: true, jsonWebKey }),
    ).resolves.toStrictEqual(uncompressedUnprotectedDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Recipient Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { recipientUnprotectedHeader: algEncJkuKidHeader }, { detached: true, jsonWebKey }),
    ).resolves.toStrictEqual(uncompressedRecipientDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Protected and Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algJkuKidHeader },
        { detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Protected and Recipient Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algJkuKidHeader },
        { detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Unprotected and Recipient Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algJkuKidHeader, unprotectedHeader: encHeader },
        { detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Full Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algKidHeader, unprotectedHeader: jkuHeader },
        { detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedFullDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Protected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncZipJkuKidHeader }, { jsonWebKey }),
    ).resolves.toStrictEqual(compressedProtectedAttachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: algEncZipJkuKidHeader }, { jsonWebKey }),
    ).resolves.toStrictEqual(compressedUnprotectedAttachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Recipient Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { recipientUnprotectedHeader: algEncZipJkuKidHeader }, { jsonWebKey }),
    ).resolves.toStrictEqual(compressedRecipientAttachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Protected and Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { protectedHeader: encHeader, unprotectedHeader: algZipJkuKidHeader }, { jsonWebKey }),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedAttachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Protected and Recipient Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algZipJkuKidHeader },
        { jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientAttachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Unprotected and Recipient Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algZipJkuKidHeader, unprotectedHeader: encHeader },
        { jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientAttachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Full Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algZipKidHeader, unprotectedHeader: jkuHeader },
        { jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedFullAttachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Protected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncZipJkuKidHeader }, { detached: true, jsonWebKey }),
    ).resolves.toStrictEqual(compressedProtectedDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: algEncZipJkuKidHeader }, { detached: true, jsonWebKey }),
    ).resolves.toStrictEqual(compressedUnprotectedDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Recipient Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { recipientUnprotectedHeader: algEncZipJkuKidHeader }, { detached: true, jsonWebKey }),
    ).resolves.toStrictEqual(compressedRecipientDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Protected and Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algZipJkuKidHeader },
        { detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Protected and Recipient Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algZipJkuKidHeader },
        { detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Unprotected and Recipient Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algZipJkuKidHeader, unprotectedHeader: encHeader },
        { detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Full Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algZipKidHeader, unprotectedHeader: jkuHeader },
        { detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedFullDetachedTokenNoAad);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Protected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncJkuKidHeader }, { additionalAuthenticatedData, jsonWebKey }),
    ).resolves.toStrictEqual(uncompressedProtectedAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: algEncJkuKidHeader }, { additionalAuthenticatedData, jsonWebKey }),
    ).resolves.toStrictEqual(uncompressedUnprotectedAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Recipient Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algEncJkuKidHeader },
        { additionalAuthenticatedData, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedRecipientAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Protected and Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algJkuKidHeader },
        { additionalAuthenticatedData, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Protected and Recipient Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algJkuKidHeader },
        { additionalAuthenticatedData, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Unprotected and Recipient Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algJkuKidHeader, unprotectedHeader: encHeader },
        { additionalAuthenticatedData, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Full Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algKidHeader, unprotectedHeader: jkuHeader },
        { additionalAuthenticatedData, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedFullAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Protected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedDetachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: algEncJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedDetachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Recipient Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algEncJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedRecipientDetachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Protected and Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndUnprotectedDetachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Protected and Recipient Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedProtectedAndRecipientDetachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Unprotected and Recipient Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algJkuKidHeader, unprotectedHeader: encHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedUnprotectedAndRecipientDetachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Uncompressed Full Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algKidHeader, unprotectedHeader: jkuHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(uncompressedFullDetachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Protected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { protectedHeader: algEncZipJkuKidHeader }, { additionalAuthenticatedData, jsonWebKey }),
    ).resolves.toStrictEqual(compressedProtectedAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(plaintext, { unprotectedHeader: algEncZipJkuKidHeader }, { additionalAuthenticatedData, jsonWebKey }),
    ).resolves.toStrictEqual(compressedUnprotectedAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Recipient Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algEncZipJkuKidHeader },
        { additionalAuthenticatedData, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedRecipientAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Protected and Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algZipJkuKidHeader },
        { additionalAuthenticatedData, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Protected and Recipient Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algZipJkuKidHeader },
        { additionalAuthenticatedData, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Unprotected and Recipient Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algZipJkuKidHeader, unprotectedHeader: encHeader },
        { additionalAuthenticatedData, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Full Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algZipKidHeader, unprotectedHeader: jkuHeader },
        { additionalAuthenticatedData, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedFullAttachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Protected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: algEncZipJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedProtectedDetachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { unprotectedHeader: algEncZipJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedDetachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Recipient Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algEncZipJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedRecipientDetachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Protected and Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, unprotectedHeader: algZipJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndUnprotectedDetachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Protected and Recipient Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algZipJkuKidHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedProtectedAndRecipientDetachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Unprotected and Recipient Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { recipientUnprotectedHeader: algZipJkuKidHeader, unprotectedHeader: encHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedUnprotectedAndRecipientDetachedToken);
  });

  it("should serialize a Flattened JSON Web Encryption Compressed Full Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      serialize(
        plaintext,
        { protectedHeader: encHeader, recipientUnprotectedHeader: algZipKidHeader, unprotectedHeader: jkuHeader },
        { additionalAuthenticatedData, detached: true, jsonWebKey },
      ),
    ).resolves.toStrictEqual(compressedFullDetachedToken);
  });
});
