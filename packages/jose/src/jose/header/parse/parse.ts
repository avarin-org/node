import { JSON } from "@avarin/primitives/json";
import type { Constructor } from "@avarin/primitives/types";

import { create } from "../create/create.ts";
import type { JoseHeader } from "../jose.header.js";
import type { JoseHeaderParameters } from "../jose.header.parameters.ts";

/**
 * Parses the provided stringified JOSE Header Parameters into a JOSE Header.
 *
 * @param HeaderConstructor JOSE Header Constructor.
 * @param data Stringified JOSE Header Parameters.
 * @param additionalParameters Optional additional JOSE Header Parameters.
 * @returns JOSE Header.
 * @throws {InvalidJoseHeaderError} The provided JOSE Header Parameters is invalid.
 * @throws {TypeError} One of the provided arguments is invalid.
 */
export async function parse<T extends JoseHeader>(
  HeaderConstructor: Constructor<T>,
  data: string,
  additionalParameters?: Partial<JoseHeaderParameters>,
): Promise<T> {
  return await create<T>(HeaderConstructor, JSON.parse(data), additionalParameters);
}
