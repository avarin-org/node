import type { KeyManagementAlgorithm } from "../jwe/alg/key-management-algorithm.type.ts";
import type { DigitalSignatureAlgorithm } from "../jws/digital-signature-algorithm.type.ts";

/**
 * Cryptographic Algorithms for Digital Signatures, MACs and Key Management.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" (Algorithm) Header Parameter}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1|RFC 7516 "alg" (Algorithm) Header Parameter}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWS}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWE}
 */
export type JoseAlgorithm = DigitalSignatureAlgorithm | KeyManagementAlgorithm | (string & {});
