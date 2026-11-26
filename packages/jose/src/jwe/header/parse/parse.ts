import { Functions } from "@avarin/primitives/functions";
import { JSON } from "@avarin/primitives/json";
import type { Constructor } from "@avarin/primitives/types";

import { InvalidJoseHeaderError } from "../../../errors/invalid-jose-header.error.ts";
import { create } from "../create/create.ts";
import { JsonWebEncryptionHeader } from "../jsonwebencryption.header.js";
import type { JsonWebEncryptionHeaderParameters } from "../jsonwebencryption.header.parameters.ts";

/**
 * Parses the provided stringified JSON Web Encryption Header Parameters into a JSON Web Encryption Header.
 *
 * @param data Stringified JSON Web Encryption Header Parameters.
 * @param additionalParameters Optional additional JSON Web Encryption Header Parameters.
 * @returns JSON Web Encryption Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
 */
export async function parse(
  data: string,
  additionalParameters?: Partial<JsonWebEncryptionHeaderParameters>,
): Promise<JsonWebEncryptionHeader>;

/**
 * Parses the provided stringified JSON Web Encryption Header Parameters into a JSON Web Encryption Header.
 *
 * @param HeaderConstructor JSON Web Encryption Header Constructor.
 * @param data Stringified JSON Web Encryption Header Parameters.
 * @param additionalParameters Optional additional JSON Web Encryption Header Parameters.
 * @returns JSON Web Encryption Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
 */
export async function parse<T extends JsonWebEncryptionHeader>(
  HeaderConstructor: Constructor<T>,
  data: string,
  additionalParameters?: Partial<JsonWebEncryptionHeaderParameters>,
): Promise<T>;

/**
 * Parses the provided stringified JSON Web Encryption Header Parameters into a JSON Web Encryption Header.
 *
 * @param dataOrHeaderConstructor Stringified JSON Web Encryption Header Parameters or JSON Web Encryption Header
 *   Constructor.
 * @param dataOrAdditionalParameters Stringified JSON Web Encryption Header Parameters or Optional additional JSON Web
 *   Encryption Header Parameters.
 * @param additionalParameters Optional additional JSON Web Encryption Header Parameters.
 * @returns JSON Web Encryption Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Encryption Header Parameters is invalid.
 */
export async function parse<T extends JsonWebEncryptionHeader = JsonWebEncryptionHeader>(
  dataOrHeaderConstructor: string | Constructor<T>,
  dataOrAdditionalParameters?: string | Partial<JsonWebEncryptionHeaderParameters>,
  additionalParameters?: Partial<JsonWebEncryptionHeaderParameters>,
): Promise<T> {
  const HeaderConstructor = Functions.isClass(dataOrHeaderConstructor)
    ? dataOrHeaderConstructor
    : (JsonWebEncryptionHeader as Constructor<T>);

  const data = Functions.isClass(dataOrHeaderConstructor)
    ? (dataOrAdditionalParameters! as string)
    : dataOrHeaderConstructor;

  if (arguments.length === 2 && !Functions.isClass(dataOrHeaderConstructor)) {
    additionalParameters = dataOrAdditionalParameters as Partial<JsonWebEncryptionHeaderParameters>;
  }

  try {
    return await create<T>(HeaderConstructor, JSON.parse(data), additionalParameters);
  } catch (error: unknown) {
    throw new InvalidJoseHeaderError("The provided JSON Web Encryption Header Parameters is invalid.", {
      cause: error,
    });
  }
}
