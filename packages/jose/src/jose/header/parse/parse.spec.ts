import { JSON } from "@avarin/primitives/json";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as createModule from "../create/create.ts";
import type { JoseHeaderParameters } from "../jose.header.parameters.ts";
import { JoseHeader } from "../jose.header.ts";
import { parse } from "./parse.ts";

class CustomJoseHeader extends JoseHeader {}

describe("parse()", () => {
  const parameters: JoseHeaderParameters = { alg: "A128KW", enc: "A256GCM" };
  const additionalParameters: Partial<JoseHeaderParameters> = { kid: "BGi9dKfLX9TPcguE" };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should call create() with a custom JOSE Header as its constructor.", async () => {
    const joseHeaderCreateSpy = vi.spyOn(createModule, "create");

    await expect(parse(CustomJoseHeader, JSON.stringify(parameters), additionalParameters)).resolves.toBeInstanceOf(
      CustomJoseHeader,
    );

    expect(joseHeaderCreateSpy).toHaveBeenCalledExactlyOnceWith(CustomJoseHeader, parameters, additionalParameters);
  });
});
