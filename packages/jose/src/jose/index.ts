import { header } from "./header/index.ts";

interface JoseMethods {
  /**
   * JOSE Header Methods.
   */
  readonly header: typeof header;
}

export const jose: JoseMethods = {
  header,
};

// #region JOSE Header
export type { JoseHeaderParameters } from "./header/jose.header.parameters.ts";
export { JoseHeader } from "./header/jose.header.ts";
// #endregion
