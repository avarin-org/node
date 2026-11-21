/**
 * RSA JSON Web Key generation options.
 */
export interface GenerateRsaJsonWebKeyOptions extends NodeJS.Dict<unknown> {
  /**
   * Length of the Modulus in bits.
   */
  readonly modulus: number;

  /**
   * Value of the Public Exponent.
   *
   * @default 0x010001
   */
  readonly publicExponent?: number;
}
