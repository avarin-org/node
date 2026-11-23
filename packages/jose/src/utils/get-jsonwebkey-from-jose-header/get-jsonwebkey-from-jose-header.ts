import { InvalidJoseHeaderError } from "../../errors/invalid-jose-header.error.ts";
import type { JoseHeaderParameters } from "../../jose/jose-header.parameters.ts";
import type { JsonWebKey } from "../../jwk/index.ts";
import { jwk } from "../../jwk/index.ts";
import { getJsonWebKeySetFromUrl } from "../get-jsonwebkeyset-from-url/get-jsonwebkeyset-from-url.ts";

/**
 * Gets a JSON Web Key from the provided JOSE Header Parameters.
 *
 * @param parameters JOSE Header Parameters.
 * @returns JSON Web Key from the provided JOSE Header Parameters.
 * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters is invalid.
 */
export async function getJsonWebKeyFromJoseHeader(parameters: JoseHeaderParameters): Promise<JsonWebKey | null> {
  if (!("jku" in parameters) && !("jwk" in parameters)) {
    return null;
  }

  let jsonWebKey!: JsonWebKey;

  if ("jku" in parameters) {
    try {
      const jsonWebKeySet = await getJsonWebKeySetFromUrl(parameters.jku);
      jsonWebKey = jsonWebKeySet.get((key) => key.kid === parameters.kid);
    } catch (error: unknown) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "jku".', { cause: error });
    }
  }

  if ("jwk" in parameters) {
    if ("kid" in parameters && parameters.kid !== parameters.jwk.kid) {
      throw new InvalidJoseHeaderError('Mismatching JOSE Header and JSON Web Key Parameters "kid".');
    }

    try {
      jsonWebKey = await jwk.create(parameters.jwk);
    } catch (error: unknown) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "jwk".', { cause: error });
    }
  }

  if ("alg" in jsonWebKey.parameters && jsonWebKey.parameters.alg !== parameters.alg) {
    throw new InvalidJoseHeaderError('Mismatching JOSE Header and JSON Web Key Parameters "alg".');
  }

  return jsonWebKey;
}
