import { Objects } from "@avarin/primitives/objects";

import { InvalidJsonWebKeyError } from "../errors/invalid-jsonwebkey.error.ts";
import { JsonWebKey } from "../jwk/jsonwebkey.js";
import type { JsonWebKeyParameters } from "../jwk/jsonwebkey.parameters.ts";
import type { JsonWebKeySetParameters } from "./jsonwebkeyset.parameters.ts";

/**
 * Implementation of the JSON Web Key Set.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html|RFC 7517 JSON Web Key (JWK)}
 */
export class JsonWebKeySet {
  /**
   * Array of JWK values.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-5.1|RFC 7517 "keys" Parameter}
   */
  public readonly keys: JsonWebKey[];

  /**
   * Instantiates a new JSON Web Key Set.
   *
   * @param keys JSON Web Keys.
   */
  public constructor(keys: JsonWebKey[]) {
    this.keys = keys;
  }

  /**
   * Finds and returns a JSON Web Key that satisfies the provided predicate.
   *
   * @param predicate Predicate used to locate the requested JSON Web Key.
   * @returns JSON Web Key that satisfies the provided predicate.
   */
  public find(predicate: (key: JsonWebKeyParameters) => boolean): JsonWebKey | null {
    return this.keys.find((key) => predicate(key.parameters)) ?? null;
  }

  /**
   * Finds and returns a JSON Web Key that satisfies the provided predicate or throws an error if none is found.
   *
   * @param predicate Predicate used to locate the requested JSON Web Key.
   * @returns JSON Web Key that satisfies the provided predicate.
   * @throws {InvalidJsonWebKeyError} No JSON Web Key matches the criteria in the JSON Web Key Set.
   */
  public get(predicate: (key: JsonWebKeyParameters) => boolean): JsonWebKey {
    const jsonWebKey = this.find((key) => predicate(key));

    if (!(jsonWebKey instanceof JsonWebKey)) {
      throw new InvalidJsonWebKeyError("No JSON Web Key matches the criteria in the JSON Web Key Set.");
    }

    return jsonWebKey;
  }

  /**
   * Returns the JSON Web Key Set Parameters.
   *
   * @default exportPrivate false
   * @param exportPrivate Exports the private parameters of the JSON Web keys.
   * @returns JSON Web Key Set Parameters.
   */
  public toJSON(exportPrivate = false): JsonWebKeySetParameters {
    return Objects.removeNullishValues<JsonWebKeySetParameters>({
      keys: this.keys.map((key) => key.toJSON(exportPrivate)),
    });
  }
}
