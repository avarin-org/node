import { Functions } from "@avarin/primitives/functions";
import { JSON } from "@avarin/primitives/json";
import type { Constructor } from "@avarin/primitives/types";

import { InvalidJoseHeaderError } from "../../../errors/invalid-jose-header.error.ts";
import { create } from "../create/create.ts";
import { JsonWebSignatureHeader } from "../jsonwebsignature.header.js";
import type { JsonWebSignatureHeaderParameters } from "../jsonwebsignature.header.parameters.ts";

/**
 * Parses the provided stringified JSON Web Signature Header Parameters into a JSON Web Signature Header.
 *
 * @param data Stringified JSON Web Signature Header Parameters.
 * @param additionalParameters Optional additional JSON Web Signature Header Parameters.
 * @returns JSON Web Signature Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
 */
export async function parse(
  data: string,
  additionalParameters?: Partial<JsonWebSignatureHeaderParameters>,
): Promise<JsonWebSignatureHeader>;

/**
 * Parses the provided stringified JSON Web Signature Header Parameters into a JSON Web Signature Header.
 *
 * @param HeaderConstructor JSON Web Signature Header Constructor.
 * @param data Stringified JSON Web Signature Header Parameters.
 * @param additionalParameters Optional additional JSON Web Signature Header Parameters.
 * @returns JSON Web Signature Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
 */
export async function parse<T extends JsonWebSignatureHeader>(
  HeaderConstructor: Constructor<T>,
  data: string,
  additionalParameters?: Partial<JsonWebSignatureHeaderParameters>,
): Promise<T>;

/**
 * Parses the provided stringified JSON Web Signature Header Parameters into a JSON Web Signature Header.
 *
 * @param dataOrHeaderConstructor Stringified JSON Web Signature Header Parameters or JSON Web Signature Header
 *   Constructor.
 * @param dataOrAdditionalParameters Stringified JSON Web Signature Header Parameters or Optional additional JSON Web
 *   Signature Header Parameters.
 * @param additionalParameters Optional additional JSON Web Signature Header Parameters.
 * @returns JSON Web Signature Header.
 * @throws {InvalidJoseHeaderError} The provided JSON Web Signature Header Parameters is invalid.
 */
export async function parse<T extends JsonWebSignatureHeader = JsonWebSignatureHeader>(
  dataOrHeaderConstructor: string | Constructor<T>,
  dataOrAdditionalParameters?: string | Partial<JsonWebSignatureHeaderParameters>,
  additionalParameters?: Partial<JsonWebSignatureHeaderParameters>,
): Promise<T> {
  const HeaderConstructor = Functions.isClass(dataOrHeaderConstructor)
    ? dataOrHeaderConstructor
    : (JsonWebSignatureHeader as Constructor<T>);

  const data = Functions.isClass(dataOrHeaderConstructor)
    ? (dataOrAdditionalParameters! as string)
    : dataOrHeaderConstructor;

  if (arguments.length === 2 && !Functions.isClass(dataOrHeaderConstructor)) {
    additionalParameters = dataOrAdditionalParameters as Partial<JsonWebSignatureHeaderParameters>;
  }

  try {
    return await create<T>(HeaderConstructor, JSON.parse(data), additionalParameters);
  } catch (error: unknown) {
    throw new InvalidJoseHeaderError("The provided JSON Web Signature Header Parameters is invalid.", { cause: error });
  }
}
