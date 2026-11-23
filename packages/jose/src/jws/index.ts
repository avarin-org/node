import { header } from "./header/index.ts";

interface JsonWebSignatureMethods {
  readonly header: typeof header;
}

export const jws: JsonWebSignatureMethods = {
  header,
};

export type { JsonWebSignatureHeaderParameters } from "./header/jsonwebsignature.header.parameters.ts";
export { JsonWebSignatureHeader } from "./header/jsonwebsignature.header.ts";
