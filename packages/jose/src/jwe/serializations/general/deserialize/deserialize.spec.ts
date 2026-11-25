import { Buffer } from "node:buffer";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/index.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import { JsonWebEncryptionHeader } from "../../../header/jsonwebencryption.header.ts";
import type { GeneralJsonWebEncryptionToken } from "../general.jsonwebencryption.token.ts";
import type { GeneralJsonWebEncryption } from "../general.jsonwebencryption.ts";
import { deserialize } from "./deserialize.ts";

const fetchMock = vi.fn<typeof globalThis.fetch>();

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, "", Symbol("a"), Buffer, Buffer.alloc(1), () => 1, []];

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

const invalidRecipients: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  {},
  [],
  [undefined],
  [null],
  [true],
  [1],
  [1.2],
  [1n],
  ["a"],
  [Symbol("a")],
  [Buffer],
  [Buffer.alloc(1)],
  [() => 1],
  [[]],
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

describe("deserialize()", () => {
  const wrongEncryptedKeyToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      { encrypted_key: "anBl9PSuJobKWwzWzJCqfMnejCvM5-WadN3zXMGyoCLW8_xmUldY3Q", header: { alg: "A128KW", kid: "7" } },
    ],
    tag: "U0m_YmjN04DJvceFICbCVQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };

  const wrongInitializationVectorToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "eE63cGwX4T7eSspUA72t2Q",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      { encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ", header: { alg: "A128KW", kid: "7" } },
    ],
    tag: "U0m_YmjN04DJvceFICbCVQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };

  const wrongAdditionalAuthenticatedDataToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      { encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ", header: { alg: "A128KW", kid: "7" } },
    ],
    tag: "U0m_YmjN04DJvceFICbCVQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };

  const wrongCiphertextToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "giYkZlt454236QV7AdREOuT0UOQrnNW1dpTna5JQpDk",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      { encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ", header: { alg: "A128KW", kid: "7" } },
    ],
    tag: "U0m_YmjN04DJvceFICbCVQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };

  const wrongAuthenticationTagToken: GeneralJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    recipients: [
      { encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ", header: { alg: "A128KW", kid: "7" } },
    ],
    tag: "24tpOFXtrTHSIdllxDRtlw",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };

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

  it.each(invalidTokens)(
    "should throw when the provided General JSON Web Encryption Token is invalid.",
    async (token) => {
      const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
      await expect(deserialize(token)).rejects.toThrow(error);
    },
  );

  it.each(invalidDeserializeOptions)(
    "should throw when the provided General JSON Web Encryption Deserialize Options is invalid.",
    async (options) => {
      const error = new TypeError("The provided General JSON Web Encryption Deserialize Options is invalid.");
      await expect(deserialize(uncompressedProtectedAttachedTokenNoAad, options)).rejects.toThrow(error);
    },
  );

  it.each(invalidDetachedCiphertexts)(
    'should throw when the provided General JSON Web Encryption Deserialize Option "detachedCiphertext" is invalid.',
    async (detachedCiphertext) => {
      const error = new TypeError(
        'The provided General JSON Web Encryption Deserialize Option "detachedCiphertext" is invalid.',
      );

      await expect(deserialize(uncompressedProtectedAttachedTokenNoAad, { detachedCiphertext })).rejects.toThrow(error);
    },
  );

  it.each(invalidRecipients)(
    'should throw when the provided General JSON Web Encryption Deserialize Option "recipients" is invalid.',
    async (recipients) => {
      const error = new TypeError(
        'The provided General JSON Web Encryption Deserialize Option "recipients" is invalid.',
      );

      await expect(deserialize(uncompressedProtectedAttachedTokenNoAad, { recipients })).rejects.toThrow(error);
    },
  );

  it.each(invalidJsonWebKeys)(
    'should throw when the provided General JSON Web Encryption Deserialize Recipient Option "jsonWebKey" is invalid.',
    async (_jsonWebKey) => {
      const error = new TypeError(
        'The provided General JSON Web Encryption Deserialize Recipient Option "jsonWebKey" is invalid.',
      );

      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, { recipients: [{ jsonWebKey: _jsonWebKey }] }),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided General JSON Web Encryption Deserialize Recipient Option "expectedKeyManagementAlgorithms" is invalid.',
    async (expectedKeyManagementAlgorithms) => {
      const error = new TypeError(
        'The provided General JSON Web Encryption Deserialize Recipient Option "expectedKeyManagementAlgorithms" is invalid.',
      );

      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, { recipients: [{ expectedKeyManagementAlgorithms }] }),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided General JSON Web Encryption Deserialize Recipient Option "expectedContentEncryptionAlgorithms" is invalid.',
    async (expectedContentEncryptionAlgorithms) => {
      const error = new TypeError(
        'The provided General JSON Web Encryption Deserialize Recipient Option "expectedContentEncryptionAlgorithms" is invalid.',
      );

      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, { recipients: [{ expectedContentEncryptionAlgorithms }] }),
      ).rejects.toThrow(error);
    },
  );

  it.each(invalidExpectedAlgorithms)(
    'should throw when the provided General JSON Web Encryption Deserialize Recipient Option "expectedCompressionAlgorithms" is invalid.',
    async (expectedCompressionAlgorithms) => {
      const error = new TypeError(
        'The provided General JSON Web Encryption Deserialize Recipient Option "expectedCompressionAlgorithms" is invalid.',
      );

      await expect(
        deserialize(uncompressedProtectedAttachedTokenNoAad, { recipients: [{ expectedCompressionAlgorithms }] }),
      ).rejects.toThrow(error);
    },
  );

  it('should throw when the General JSON Web Encryption Deserialize Option "recipients" has length different than the recipients of the General JSON Web Encryption Token.', async () => {
    const error = new TypeError(
      'The length of the General JSON Web Encryption Deserialize Option "recipients" and the General JSON Web Encryption Token Signatures do not match.',
    );

    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, { recipients: [{ jsonWebKey }, { jsonWebKey }] }),
    ).rejects.toThrow(error);
  });

  it("should throw when deserializing a Detached General JSON Web Encryption Token and not providing a Detached Ciphertext.", async () => {
    const error = new InvalidJsonWebEncryptionError("The JSON Web Encryption requires a valid Ciphertext.");
    await expect(deserialize(uncompressedProtectedDetachedTokenNoAad)).rejects.toThrow(error);
  });

  it("should throw when providing a Detached Ciphertext for a General JSON Web Encryption Token that already has a Ciphertext.", async () => {
    const error = new InvalidJsonWebEncryptionError(
      "The provided JSON Web Encryption already has a defined Ciphertext.",
    );

    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, { detachedCiphertext: ciphertext }),
    ).rejects.toThrow(error);
  });

  it("should throw when the Key Management Algorithm of the General JSON Web Encryption Token is unexpected.", async () => {
    const error = new InvalidJsonWebEncryptionError('Unexpected Key Management Algorithm "A128KW".');

    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, {
        recipients: [{ expectedKeyManagementAlgorithms: ["A256KW"] }],
      }),
    ).rejects.toThrow(error);
  });

  it("should throw when the Content Encryption Algorithm of the General JSON Web Encryption Token is unexpected.", async () => {
    const error = new InvalidJsonWebEncryptionError('Unexpected Content Encryption Algorithm "A128CBC-HS256".');

    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, {
        recipients: [{ expectedContentEncryptionAlgorithms: ["A256CBC-HS512"] }],
      }),
    ).rejects.toThrow(error);
  });

  it("should throw when the Compression Algorithm of the General JSON Web Encryption Token is unexpected.", async () => {
    const error = new InvalidJsonWebEncryptionError('Unexpected Compression Algorithm "".');

    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, {
        recipients: [{ expectedCompressionAlgorithms: ["DEF"] }],
      }),
    ).rejects.toThrow(error);
  });

  it("should throw when the provided Encrypted Key fails to deserialize the provided General JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongEncryptedKeyToken)).rejects.toThrow(error);
  });

  it("should throw when the provided Initialization Vector fails to deserialize the provided General JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongInitializationVectorToken)).rejects.toThrow(error);
  });

  it("should throw when the provided Additional Authenticated Data fails to deserialize the provided General JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongAdditionalAuthenticatedDataToken)).rejects.toThrow(error);
  });

  it("should throw when the provided Ciphertext fails to deserialize the provided General JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongCiphertextToken)).rejects.toThrow(error);
  });

  it("should throw when the provided Authentication Tag fails to deserialize the provided General JSON Web Encryption Token.", async () => {
    const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
    await expect(deserialize(wrongAuthenticationTagToken)).rejects.toThrow(error);
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: algEncJkuKidHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedRecipientAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndUnprotectedAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndRecipientAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedAndRecipientAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedFullAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: algEncJkuKidHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedRecipientDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndUnprotectedDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndRecipientDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedAndRecipientDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedFullDetachedTokenNoAad, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: algEncZipJkuKidHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedRecipientAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected and Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndUnprotectedAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndRecipientAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedAndRecipientAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedFullAttachedTokenNoAad, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: algEncZipJkuKidHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedRecipientDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected and Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndUnprotectedDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndRecipientDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedAndRecipientDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedFullDetachedTokenNoAad, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: algEncJkuKidHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedRecipientAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndUnprotectedAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndRecipientAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedAndRecipientAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedFullAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedDetachedToken, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: algEncJkuKidHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedDetachedToken, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedRecipientDetachedToken, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndUnprotectedDetachedToken, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedProtectedAndRecipientDetachedToken, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedUnprotectedAndRecipientDetachedToken, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from an Uncompressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(uncompressedFullDetachedToken, {
        detachedCiphertext: ciphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: algEncZipJkuKidHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedRecipientAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected and Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndUnprotectedAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndRecipientAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedAndRecipientAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedFullAttachedToken, { recipients: [{ jsonWebKey }] }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: algEncZipJkuKidHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedRecipientDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algEncZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected and Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndUnprotectedDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: null,
        },
      ],
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedProtectedAndRecipientDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: null,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedUnprotectedAndRecipientDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: null,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipJkuKidHeader,
        },
      ],
      unprotectedHeader: encHeader,
    });
  });

  it("should return the deserialized General JSON Web Encryption from a Compressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      deserialize(compressedFullDetachedToken, {
        detachedCiphertext: compressedCiphertext,
        recipients: [{ jsonWebKey }],
      }),
    ).resolves.toStrictEqual<GeneralJsonWebEncryption>({
      plaintext,
      protectedHeader: encHeader,
      recipients: [
        {
          header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
          recipientUnprotectedHeader: algZipKidHeader,
        },
      ],
      unprotectedHeader: jkuHeader,
    });
  });
});
