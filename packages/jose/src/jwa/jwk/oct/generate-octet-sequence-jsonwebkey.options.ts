/**
 * Octet Sequence JSON Web Key Generation Options.
 */
export interface GenerateOctetSequenceJsonWebKeyOptions extends NodeJS.Dict<unknown> {
  /**
   * Length of the secret in bits.
   */
  readonly length: number;
}
