import { Functions } from "@avarin/primitives/functions";
import { Objects } from "@avarin/primitives/objects";
import type { Constructor } from "@avarin/primitives/types";

import type { JoseHeaderParameters } from "../jose.header.parameters.ts";
import { JoseHeader } from "../jose.header.ts";

/**
 * Checks if the provided data is a valid JOSE Header Parameters object.
 *
 * @param HeaderConstructor JOSE Header Constructor.
 * @param parameters JOSE Header Parameters.
 * @returns Whether or not the provided data is a valid JOSE Header Parameters object.
 */
export function check<T extends JoseHeaderParameters = JoseHeaderParameters>(
  HeaderConstructor: Constructor<JoseHeader>,
  parameters: unknown,
): parameters is T {
  try {
    if (Functions.isClass(HeaderConstructor) && !(HeaderConstructor.prototype instanceof JoseHeader)) {
      return false;
    }

    if (!Objects.isPlain(parameters)) {
      return false;
    }

    Reflect.construct(HeaderConstructor, [parameters]);

    return true;
  } catch {
    return false;
  }
}
