import { afterEach, describe, expect, it, vi } from "vitest";

import { jose } from "../../../jose/index.ts";
import type { JsonWebEncryptionHeaderParameters } from "../jsonwebencryption.header.parameters.ts";
import { JsonWebEncryptionHeader } from "../jsonwebencryption.header.ts";
import { create } from "./create.ts";

describe("create()", () => {
  const parameters: JsonWebEncryptionHeaderParameters = { alg: "A128KW", enc: "A256GCM" };
  const additionalParameters: Partial<JsonWebEncryptionHeaderParameters> = { kid: "BGi9dKfLX9TPcguE" };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should call jose.header.create() with the JSON Web Encryption Header as its constructor.", async () => {
    const joseHeaderCreateSpy = vi.spyOn(jose.header, "create");

    await expect(create(parameters, additionalParameters)).resolves.toBeInstanceOf(JsonWebEncryptionHeader);

    expect(joseHeaderCreateSpy).toHaveBeenCalledExactlyOnceWith(
      JsonWebEncryptionHeader,
      parameters,
      additionalParameters,
    );
  });
});
