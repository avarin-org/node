import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { Functions } from "./functions.ts";

const invalidClasses: any[] = [undefined, null, true, 1, 1.2, 1n, "", Symbol("a"), Buffer.alloc(1), () => 1, {}, []];

describe("isClass()", () => {
  it.each(invalidClasses)("should return false when the provided data is not a class.", (class_) => {
    expect(Functions.isClass(class_)).toBe(false);
  });

  it("should return true when the provided data is a class.", () => {
    expect(Functions.isClass(Buffer)).toBe(true);
  });
});
