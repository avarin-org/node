import { Buffer } from "node:buffer";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/index.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import { JsonWebEncryptionHeader } from "../../../header/jsonwebencryption.header.ts";
import type { FlattenedJsonWebEncryptionToken } from "../flattened.jsonwebencryption.token.ts";
import type { FlattenedJsonWebEncryption } from "../flattened.jsonwebencryption.ts";
import { deserialize } from "./deserialize.ts";

const fetchMock = vi.fn<typeof globalThis.fetch>();

const invalidDeserializeOptions: any[] = [
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

const invalidExpectedAlgorithms: any[] = [
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
  ["HS256"],
];

const invalidDetachedCiphertexts: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol("a"),
  Buffer,
  () => 1,
  {},
  [],
  Buffer.alloc(0),
];

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, "", Symbol("a"), Buffer, Buffer.alloc(1), () => 1, []];

describe("deserialize()", () => {
  const wrongEncryptedKeyToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "anBl9PSuJobKWwzWzJCqfMnejCvM5-WadN3zXMGyoCLW8_xmUldY3Q",
    header: { alg: "A128KW", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "U0m_YmjN04DJvceFICbCVQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };

  const wrongAdditionalAuthenticatedDataToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "U0m_YmjN04DJvceFICbCVQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };

  const wrongInitializationVectorToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7" },
    iv: "eE63cGwX4T7eSspUA72t2Q",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "U0m_YmjN04DJvceFICbCVQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };

  const wrongCiphertextToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "giYkZlt454236QV7AdREOuT0UOQrnNW1dpTna5JQpDk",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "U0m_YmjN04DJvceFICbCVQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };

  const wrongAuthenticationTagToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "24tpOFXtrTHSIdllxDRtlw",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };

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
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "8nmSbluZF1Ws1sABt49r6Q",
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
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "8nmSbluZF1Ws1sABt49r6Q",
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
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "SRoHlcdRqnsVScLWNZIwtA",
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
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "SRoHlcdRqnsVScLWNZIwtA",
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

  const ciphertext = Buffer.from("KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY", "base64url");
  const compressedCiphertext = Buffer.from("7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA", "base64url");

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

  it.each(invalidDeserializeOptions)(
    "should throw when the provided Flattened JSON Web Encryption Deserialize Options is invalid.",
    async (options) => {
      const error = new TypeError("The provided Flattened JSON Web Encryption Deserialize Options is invalid.");
      await expect(deserialize(uncompressedProtectedAttachedTokenNoAad, options)).rejects.toThrow(error);
    },
  );

  it.each(invalidJsonWebKeys)(
    'should throw when the provided Flattened JSON Web Encryption Deserialize Option "jsonWebKey" is invalid.',
    async (_jsonWebKey) => {
      const error = new TypeError(
        'The provided Flattened JSON Web Encryption Deserialize Option "jsonWebKey" is invalid.',
      );

      await expect(deserialize(uncompressedProtectedAttachedTokenNoAad, { jsonWebKey: _jsonWebKey })).rejects.toThrow(
        error,
      );
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided Flattened JSON Web Encryption Deserialize Option "expectedKeyManagementAlgorithms" is invalid.',
    async (expectedKeyManagementAlgorithms) => {
      const error = new TypeError(
        'The provided Flattened JSON Web Encryption Deserialize Option "expectedKeyManagementAlgorithms" is invalid.',
      );

      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, { expectedKeyManagementAlgorithms }),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided Flattened JSON Web Encryption Deserialize Option "expectedContentEncryptionAlgorithms" is invalid.',
    async (expectedContentEncryptionAlgorithms) => {
      const error = new TypeError(
        'The provided Flattened JSON Web Encryption Deserialize Option "expectedContentEncryptionAlgorithms" is invalid.',
      );

      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, { expectedContentEncryptionAlgorithms }),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided Flattened JSON Web Encryption Deserialize Option "expectedCompressionAlgorithms" is invalid.',
    async (expectedCompressionAlgorithms) => {
      const error = new TypeError(
        'The provided Flattened JSON Web Encryption Deserialize Option "expectedCompressionAlgorithms" is invalid.',
      );

      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, { expectedCompressionAlgorithms }),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidDetachedCiphertexts)(
    'should throw when the provided Flattened JSON Web Encryption Deserialize Option "detachedCiphertext" is invalid.',
    async (detachedCiphertext) => {
      const error = new TypeError(
        'The provided Flattened JSON Web Encryption Deserialize Option "detachedCiphertext" is invalid.',
      );

      await expect(deserialize(uncompressedProtectedAttachedTokenNoAad, { detachedCiphertext })).rejects.toThrow(error);
    },
  );

  it.each(invalidTokens)(
    "should throw when the provided Flattened JSON Web Encryption Token is invalid.",
    async (token) => {
      const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
      await expect(deserialize(token)).rejects.toThrow(error);
    },
  );

  it("should throw when deserializing a Detached Flattened JSON Web Encryption Token and not providing a Detached Ciphertext.", async () => {
    const error = new InvalidJsonWebEncryptionError("The JSON Web Encryption requires a valid Ciphertext.");
    await expect(deserialize(uncompressedProtectedDetachedTokenNoAad)).rejects.toThrow(error);
  });

  it("should throw when providing a Detached Ciphertext for a Flattened JSON Web Encryption Token that already has a Ciphertext.", async () => {
    const error = new InvalidJsonWebEncryptionError(
      "The provided JSON Web Encryption already has a defined Ciphertext.",
    );

    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, { detachedCiphertext: ciphertext }),
    ).rejects.toThrow(error);
  });

  it("should throw when the Key Management Algorithm of the Flattened JSON Web Encryption Token is unexpected.", async () => {
    const error = new InvalidJsonWebEncryptionError('Unexpected Key Management Algorithm "A128KW".');

    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, { expectedKeyManagementAlgorithms: ["A256KW"] }),
    ).rejects.toThrow(error);
  });

  it("should throw when the Content Encryption Algorithm of the Flattened JSON Web Encryption Token is unexpected.", async () => {
    const error = new InvalidJsonWebEncryptionError('Unexpected Content Encryption Algorithm "A128CBC-HS256".');

    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, { expectedContentEncryptionAlgorithms: ["A256CBC-HS512"] }),
    ).rejects.toThrow(error);
  });

  it("should throw when the Compression Algorithm of the Flattened JSON Web Encryption Token is unexpected.", async () => {
    const error = new InvalidJsonWebEncryptionError('Unexpected Compression Algorithm "".');

    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, { expectedCompressionAlgorithms: ["DEF"] }),
    ).rejects.toThrow(error);
  });

  it("should throw when the provided Encrypted Key fails to deserialize the provided Flattened JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongEncryptedKeyToken, { jsonWebKey })).rejects.toThrow(error);
  });

  it("should throw when the provided Additional Authenticated Data fails to deserialize the provided Flattened JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongAdditionalAuthenticatedDataToken, { jsonWebKey })).rejects.toThrow(error);
  });

  it("should throw when the provided Initialization Vector fails to deserialize the provided Flattened JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongInitializationVectorToken, { jsonWebKey })).rejects.toThrow(error);
  });

  it("should throw when the provided Ciphertext fails to deserialize the provided Flattened JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongCiphertextToken, { jsonWebKey })).rejects.toThrow(error);
  });

  it("should throw when the provided Authentication Tag fails to deserialize the provided Flattened JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongAuthenticationTagToken, { jsonWebKey })).rejects.toThrow(error);
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: algEncJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedRecipientAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndUnprotectedAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndRecipientAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedAndRecipientAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedFullAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedDetachedTokenNoAad, { detachedCiphertext: ciphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: algEncJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedDetachedTokenNoAad, { detachedCiphertext: ciphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedRecipientDetachedTokenNoAad, { detachedCiphertext: ciphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndUnprotectedDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        jsonWebKey,
      }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndRecipientDetachedTokenNoAad, { detachedCiphertext: ciphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedAndRecipientDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        jsonWebKey,
      }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedFullDetachedTokenNoAad, { detachedCiphertext: ciphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: algEncZipJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedRecipientAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndUnprotectedAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndRecipientAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedAndRecipientAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedFullAttachedTokenNoAad, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedDetachedTokenNoAad, { detachedCiphertext: compressedCiphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: algEncZipJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedDetachedTokenNoAad, { detachedCiphertext: compressedCiphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedRecipientDetachedTokenNoAad, { detachedCiphertext: compressedCiphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndUnprotectedDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        jsonWebKey,
      }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndRecipientDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        jsonWebKey,
      }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedAndRecipientDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        jsonWebKey,
      }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedFullDetachedTokenNoAad, { detachedCiphertext: compressedCiphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: algEncJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedRecipientAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndUnprotectedAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndRecipientAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedAndRecipientAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedFullAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedDetachedToken, { detachedCiphertext: ciphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: algEncJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedDetachedToken, { detachedCiphertext: ciphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedRecipientDetachedToken, { detachedCiphertext: ciphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndUnprotectedDetachedToken, { detachedCiphertext: ciphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndRecipientDetachedToken, { detachedCiphertext: ciphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedAndRecipientDetachedToken, { detachedCiphertext: ciphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedFullDetachedToken, { detachedCiphertext: ciphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: algEncZipJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedRecipientAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndUnprotectedAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndRecipientAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedAndRecipientAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedFullAttachedToken, { jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedDetachedToken, { detachedCiphertext: compressedCiphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: algEncZipJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedDetachedToken, { detachedCiphertext: compressedCiphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedRecipientDetachedToken, { detachedCiphertext: compressedCiphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndUnprotectedDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        jsonWebKey,
      }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndRecipientDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        jsonWebKey,
      }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedAndRecipientDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        jsonWebKey,
      }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: null,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized Flattened JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedFullDetachedToken, { detachedCiphertext: compressedCiphertext, jsonWebKey }),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryption>({
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      plaintext,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });
});
