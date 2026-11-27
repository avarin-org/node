import { Strings } from "@avarin/primitives/strings";

import { InvalidJoseHeaderError } from "../../errors/invalid-jose-header.error.ts";
import { JoseHeader } from "../../jose/header/jose.header.ts";
import { DIGITAL_SIGNATURE_BACKEND_REGISTRY } from "../../jwa/jws/digital-signature.backend.registry.ts";
import type { DigitalSignatureBackend } from "../../jwa/jws/digital-signature.backend.ts";
import type { JsonWebSignatureHeaderParameters } from "./jsonwebsignature.header.parameters.ts";

/**
 * Implementation of the JSON Web Signature Header.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4|RFC 7515 JOSE Header}
 */
export class JsonWebSignatureHeader extends JoseHeader<JsonWebSignatureHeaderParameters> {
  /**
   * Digital Signature Backend.
   */
  public readonly digitalSignatureBackend: DigitalSignatureBackend;

  /**
   * Instantiates a new JSON Web Signature Header.
   *
   * @param parameters JSON Web Signature Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
   */
  public constructor(parameters: JsonWebSignatureHeaderParameters) {
    super(parameters);

    this.digitalSignatureBackend = DIGITAL_SIGNATURE_BACKEND_REGISTRY.find(
      (backend) => backend.name === parameters.alg,
    )!;
  }

  /**
   * Validates the provided JOSE Header Parameters.
   *
   * @param parameters JOSE Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters is invalid.
   */
  protected override validate(parameters: JsonWebSignatureHeaderParameters): void {
    if (
      !Strings.isNonEmpty(parameters.alg) ||
      !DIGITAL_SIGNATURE_BACKEND_REGISTRY.some((backend) => backend.name === parameters.alg)
    ) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "alg".');
    }

    if ("b64" in parameters && (typeof parameters.b64 !== "boolean" || parameters.crit?.includes("b64") !== true)) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "b64".');
    }

    super.validate(parameters);
  }
}
