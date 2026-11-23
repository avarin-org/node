import { header } from "./header/index.ts";
import { register } from "./register/register.ts";

interface JsonWebSignatureMethods {
  readonly header: typeof header;

  /**
   * Registers the provided Digital Signature Backend into the Registry.
   *
   * @param backend Digital Signature Backend to be registered.
   * @throws {TypeError} The provided Digital Signature Backend is invalid or is already registered.
   */
  readonly register: typeof register;
}

export const jws: JsonWebSignatureMethods = {
  header,
  register,
};

export type { JsonWebSignatureHeaderParameters } from "./header/jsonwebsignature.header.parameters.ts";
export { JsonWebSignatureHeader } from "./header/jsonwebsignature.header.ts";
