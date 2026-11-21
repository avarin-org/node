import type { KeyObject } from "node:crypto";
import { URL } from "node:url";

import { Objects } from "@avarin/primitives/objects";
import { Strings } from "@avarin/primitives/strings";

import { InvalidJsonWebKeyError } from "../../errors/invalid-jsonwebkey.error.ts";
import type { JsonWebKeyParameters } from "../../jwk/jsonwebkey.parameters.ts";
import type { JsonWebKey } from "../../jwk/jsonwebkey.ts";
import type { JoseAlgorithm } from "../jose/jose-algorithm.type.ts";
import type { KeyOperation } from "./key-operation.type.ts";
import type { KeyType } from "./key-type.type.ts";
import type { PublicKeyUse } from "./public-key-use.type.ts";

export abstract class JsonWebKeyBackend<T extends JsonWebKeyParameters = JsonWebKeyParameters> {
  /**
   * JSON Web Key Key Type supported by the JSON Web Key Backend.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1|RFC 7517 "kty" (Key Type) Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1|RFC 7518 "kty" (Key Type) Parameter Values}
   */
  public static readonly keyType: KeyType;

  /**
   * JSON Web Key Parameters.
   */
  public readonly parameters: T;

  /**
   * Supported JSON Web Key Public Key Uses.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.2|RFC 7517 Public Key Use Parameter}
   */
  readonly #publicKeyUses = new Set<PublicKeyUse>(["enc", "sig"]);

  /**
   * Supported JSON Web Key Key Operations.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3|RFC 7517 Key Operations Parameter}
   */
  readonly #keyOperations = new Set<KeyOperation>([
    "decrypt",
    "deriveBits",
    "deriveKey",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]);

  /**
   * Supported JOSE Algorithms.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1|RFC 7515 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1|RFC 7516 "alg" (Algorithm) Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWS}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1|RFC 7518 "alg" (Algorithm) Header Parameter Values for JWE}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1|RFC 8037 Signatures}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2|RFC 8037 ECDH-ES}
   * @see {@link https://www.rfc-editor.org/rfc/rfc8812.html#section-3.2|RFC 8812 ECDSA Signature with secp256k1 Curve}
   */
  // TODO: Move this to JOSE Header or use registry.
  readonly #algorithms = new Set<JoseAlgorithm>([
    "A128GCMKW",
    "A128KW",
    "A192GCMKW",
    "A192KW",
    "A256GCMKW",
    "A256KW",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
    "ES256",
    "ES256K",
    "ES384",
    "ES512",
    "EdDSA",
    "HS256",
    "HS384",
    "HS512",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW",
    "PS256",
    "PS384",
    "PS512",
    "RS256",
    "RS384",
    "RS512",
    "RSA-OAEP",
    "RSA-OAEP-256",
    "RSA-OAEP-384",
    "RSA-OAEP-512",
    "RSA1_5",
    "dir",
    "none",
  ]);

  /**
   * Instantiates a new JSON Web Key Backend.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters is invalid.
   */
  public constructor(parameters: T) {
    this.validate(parameters);
    this.parameters = Objects.removeNullishValues(globalThis.structuredClone(parameters));
  }

  /**
   * Generates a JSON Web Key based on the provided options.
   *
   * @param options JSON Web Key Generation Options.
   * @param parameters Optional additional JSON Web Key Parameters.
   * @returns Generated JSON Web Key.
   * @throws {InvalidJsonWebKeyError} The provided additional JSON Web Key Parameters is invalid.
   * @throws {TypeError} The provided Generation Options is invalid.
   */
  // oxlint-disable-next-line require-await
  public static async generate(
    // @ts-expect-error Unused parameter.
    // oxlint-disable-next-line no-unused-vars
    options: NodeJS.Dict<unknown>,
    // @ts-expect-error Unused parameter.
    // oxlint-disable-next-line no-unused-vars
    parameters?: Partial<JsonWebKeyParameters>,
  ): Promise<JsonWebKey> {
    throw new Error("Method not implemented.");
  }

  /**
   * Creates a native Crypto Key.
   *
   * @returns Native Crypto Key.
   */
  public abstract getCryptoKey(): KeyObject;

  /**
   * Returns the JSON Web Key Parameters.
   *
   * @default exportPrivate false
   * @param exportPrivate Exports the private parameters of the JSON Web key.
   * @returns JSON Web Key Parameters.
   */
  public abstract toJSON(exportPrivate?: boolean): T;

  /**
   * Validates the provided JSON Web Key Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   * @throws {InvalidJsonWebKeyError} The provided JSON Web Key Parameters is invalid.
   */
  protected validate(parameters: T): void {
    if ("use" in parameters && !this.isUseAValidPublicKeyUse(parameters.use)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "use".');
    }

    if (
      "key_ops" in parameters &&
      (!this.isKeyOpsANonEmptyArrayOfDistinctKeyOperations(parameters.key_ops) ||
        !this.isKeyOpsCombinationValid(parameters.key_ops))
    ) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "key_ops".');
    }

    if (
      "key_ops" in parameters &&
      "use" in parameters &&
      !this.isUseAndKeyOpsCombinationValid(parameters.use, parameters.key_ops)
    ) {
      throw new InvalidJsonWebKeyError('Invalid combination of JSON Web Key Parameters "use" and "key_ops".');
    }

    if ("alg" in parameters && !this.isAlgAValidJoseAlgorithm(parameters.alg)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "alg".');
    }

    if ("kid" in parameters && !Strings.isNonEmpty(parameters.kid)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "kid".');
    }

    if ("x5u" in parameters && (!Strings.isNonEmpty(parameters.x5u) || !URL.canParse(parameters.x5u))) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "x5u".');
    }

    if ("x5c" in parameters && !this.isX5CANonEmptyArrayOfStrings(parameters.x5c)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "x5c".');
    }

    if ("x5t" in parameters && !Strings.isNonEmpty(parameters.x5t)) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "x5t".');
    }

    if ("x5t#S256" in parameters && !Strings.isNonEmpty(parameters["x5t#S256"])) {
      throw new InvalidJsonWebKeyError('Invalid JSON Web Key Parameter "x5t#S256".');
    }

    if ("x5u" in parameters && "x5c" in parameters) {
      throw new InvalidJsonWebKeyError('Cannot have both "x5u" and "x5c" JSON Web Key Parameters.');
    }

    if (("x5t" in parameters || "x5t#S256" in parameters) && !("x5u" in parameters) && !("x5c" in parameters)) {
      throw new InvalidJsonWebKeyError(
        "Cannot have an X.509 Certificate Thumbprint without an X.509 Certificate Chain.",
      );
    }
  }

  // #region Helper Methods
  private isUseAValidPublicKeyUse(use: unknown): use is PublicKeyUse {
    return typeof use === "string" && this.#publicKeyUses.has(use);
  }

  private isKeyOpsANonEmptyArrayOfDistinctKeyOperations(keyOps: unknown): keyOps is KeyOperation[] {
    return (
      Array.isArray(keyOps) &&
      keyOps.length > 0 &&
      keyOps.every((keyOp) => typeof keyOp === "string" && this.#keyOperations.has(keyOp)) &&
      new Set(keyOps).size === keyOps.length
    );
  }

  private isKeyOpsCombinationValid(keyOps: KeyOperation[]): boolean {
    if (keyOps.length === 1) {
      return true;
    }

    if (keyOps.length > 2) {
      return false;
    }

    const combinations: KeyOperation[][] = [
      ["sign", "verify"],
      ["encrypt", "decrypt"],
      ["wrapKey", "unwrapKey"],
      ["deriveBits", "deriveKey"],
    ];

    return combinations.some((combination) => keyOps.every((keyOp) => combination.includes(keyOp)));
  }

  private isUseAndKeyOpsCombinationValid(use: PublicKeyUse, keyOps: KeyOperation[]): boolean {
    const encOps = new Set<KeyOperation>(["decrypt", "deriveBits", "deriveKey", "encrypt", "unwrapKey", "wrapKey"]);
    const sigOps = new Set<KeyOperation>(["sign", "verify"]);

    return (
      (use === "enc" && keyOps.every((keyOp) => encOps.has(keyOp))) ||
      (use === "sig" && keyOps.every((keyOp) => sigOps.has(keyOp)))
    );
  }

  private isAlgAValidJoseAlgorithm(alg: unknown): alg is JoseAlgorithm {
    return typeof alg === "string" && this.#algorithms.has(alg);
  }

  private isX5CANonEmptyArrayOfStrings(x5c: unknown): x5c is string[] {
    return Array.isArray(x5c) && x5c.length > 0 && x5c.every((certificate) => Strings.isNonEmpty(certificate));
  }
  // #endregion
}
