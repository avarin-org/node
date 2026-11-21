import type { EllipticCurve } from "./elliptic-curve.type.ts";

/**
 * Elliptic Curve JSON Web Key Generation Options.
 */
export interface GenerateEllipticCurveJsonWebKeyOptions extends NodeJS.Dict<unknown> {
  /**
   * Name of the Elliptic Curve.
   */
  readonly curve: EllipticCurve;
}
