import { Strings } from "@avarin/primitives/strings";

import { InvalidJoseHeaderError } from "../../errors/invalid-jose-header.error.ts";
import { JoseHeader } from "../../jose/jose-header.ts";
import { KEY_MANAGEMENT_BACKEND_REGISTRY } from "../../jwa/jwe/alg/key-management.backend.registry.ts";
import type { KeyManagementBackend } from "../../jwa/jwe/alg/key-management.backend.ts";
import { CONTENT_ENCRYPTION_BACKEND_REGISTRY } from "../../jwa/jwe/enc/content-encryption.backend.registry.ts";
import type { ContentEncryptionBackend } from "../../jwa/jwe/enc/content-encryption.backend.ts";
import { COMPRESSION_BACKEND_REGISTRY } from "../../jwa/jwe/zip/compression.backend.registry.ts";
import type { CompressionBackend } from "../../jwa/jwe/zip/compression.backend.ts";
import type { JsonWebEncryptionHeaderParameters } from "./jsonwebencryption.header.parameters.ts";

/**
 * Implementation of the JSON Web Encryption Header.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4|RFC 7516 JOSE Header}
 */
export class JsonWebEncryptionHeader<
  T extends JsonWebEncryptionHeaderParameters = JsonWebEncryptionHeaderParameters,
> extends JoseHeader<T> {
  /**
   * Key Management Backend.
   */
  public readonly keyManagementBackend: KeyManagementBackend;

  /**
   * Content Encryption Backend.
   */
  public readonly contentEncryptionBackend: ContentEncryptionBackend;

  /**
   * Compression Backend.
   */
  public readonly compressionBackend: CompressionBackend | null;

  /**
   * Instantiates a new JSON Web Encryption Header.
   *
   * @param parameters JSON Web Encryption Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
   */
  public constructor(parameters: T) {
    super(parameters);

    this.keyManagementBackend = KEY_MANAGEMENT_BACKEND_REGISTRY.find((backend) => backend.name === parameters.alg)!;

    this.contentEncryptionBackend = CONTENT_ENCRYPTION_BACKEND_REGISTRY.find(
      (backend) => backend.name === parameters.enc,
    )!;

    this.compressionBackend = COMPRESSION_BACKEND_REGISTRY.find((backend) => backend.name === parameters.zip) ?? null;
  }

  /**
   * Validates the provided JOSE Header Parameters.
   *
   * @param parameters JOSE Header Parameters.
   * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters is invalid.
   */
  protected override validate(parameters: T): void {
    if (
      !Strings.isNonEmpty(parameters.alg) ||
      !KEY_MANAGEMENT_BACKEND_REGISTRY.some((backend) => backend.name === parameters.alg)
    ) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "alg".');
    }

    if (
      !Strings.isNonEmpty(parameters.enc) ||
      !CONTENT_ENCRYPTION_BACKEND_REGISTRY.some((backend) => backend.name === parameters.enc)
    ) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "enc".');
    }

    if (
      "zip" in parameters &&
      (!Strings.isNonEmpty(parameters.zip) ||
        !COMPRESSION_BACKEND_REGISTRY.some((backend) => backend.name === parameters.zip))
    ) {
      throw new InvalidJoseHeaderError('Invalid JOSE Header Parameter "zip".');
    }

    super.validate(parameters);
  }
}
