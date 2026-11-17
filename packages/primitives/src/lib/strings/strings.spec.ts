import { describe, expect, it } from "vitest";

import { Strings } from "./strings.js";

describe("isEmpty()", () => {
  it("should return false when the provided string is not empty.", () => {
    expect(Strings.isEmpty("foobar")).toBe(false);
  });

  it("should return true when the provided string is empty.", () => {
    expect(Strings.isEmpty("")).toBe(true);
  });
});
