import type { EllipticCurve } from "./ec/elliptic-curve.type.ts";

/**
 * Identifies the cryptographic curve used with the key.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1|RFC 7518 "crv" (Curve) Parameter}
 */
export type Curve = EllipticCurve | (string & {});
