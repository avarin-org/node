import { Buffer } from "node:buffer";
import { timingSafeEqual } from "node:crypto";

import { afterEach, describe, expect, it, vi } from "vitest";

import { Strings } from "./strings.js";

vi.mock(import("node:crypto"), { spy: true });

describe("isEmpty()", () => {
  it("should return false when the provided string is not empty.", () => {
    expect(Strings.isEmpty("foobar")).toBe(false);
  });

  it("should return true when the provided string is empty.", () => {
    expect(Strings.isEmpty("")).toBe(true);
  });
});

describe("compare()", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should return false if the strings have different length.", () => {
    expect(Strings.compare("hello", "goodbye")).toBe(false);
    expect(timingSafeEqual).not.toHaveBeenCalled();
  });

  it("should return false if the strings are different.", () => {
    expect(Strings.compare("hello", "olleh")).toBe(false);
    expect(timingSafeEqual).toHaveBeenCalledExactlyOnceWith(Buffer.from("hello", "utf8"), Buffer.from("olleh", "utf8"));
  });

  it("should return true if the strings are equal.", () => {
    expect(Strings.compare("hello", "hello")).toBe(true);
    expect(timingSafeEqual).toHaveBeenCalledExactlyOnceWith(Buffer.from("hello", "utf8"), Buffer.from("hello", "utf8"));
  });

  it("should return true if the strings are equal while passing a buffer encoding.", () => {
    expect(Strings.compare("AQAB", "AQAB", "base64url")).toBe(true);

    expect(timingSafeEqual).toHaveBeenCalledExactlyOnceWith(
      Buffer.from("AQAB", "base64url"),
      Buffer.from("AQAB", "base64url"),
    );
  });
});
