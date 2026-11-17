import { describe, expect, it } from "vitest";

import { Enum } from "./enum.js";

enum IntEnum {
  One = 1,
  Two = 2,
  Four = 4,
  Eight = 8,
}

enum StringEnum {
  Foo = "foo",
  Bar = "bar",
  Baz = "baz",
  Qux = "qux",
}

describe("getKeys()", () => {
  it("should return all the keys of the enum.", () => {
    expect(Enum.getKeys(IntEnum)).toStrictEqual(["One", "Two", "Four", "Eight"]);
    expect(Enum.getKeys(StringEnum)).toStrictEqual(["Foo", "Bar", "Baz", "Qux"]);
  });
});

describe("getKey()", () => {
  it("should return null when there's no key that matches the provided value in the enum.", () => {
    expect(Enum.getKey(IntEnum, 3 as any)).toBeNull();
    expect(Enum.getKey(StringEnum, "unknown" as any)).toBeNull();
  });

  it("should return the first key that matches the requested value.", () => {
    expect(Enum.getKey(IntEnum, IntEnum.One)).toBe("One");
    expect(Enum.getKey(StringEnum, StringEnum.Foo)).toBe("Foo");
  });
});

describe("hasKey()", () => {
  it("should return whether or not the provided key exists in the enum.", () => {
    expect(Enum.hasKey(IntEnum, "Eight")).toBe(true);
    expect(Enum.hasKey(StringEnum, "Baz")).toBe(true);

    expect(Enum.hasKey(IntEnum, "Unknown")).toBe(false);
    expect(Enum.hasKey(StringEnum, "Unknown")).toBe(false);
  });
});

describe("getValues()", () => {
  it("should return all the values of the enum.", () => {
    expect(Enum.getValues(IntEnum)).toStrictEqual([1, 2, 4, 8]);
    expect(Enum.getValues(StringEnum)).toStrictEqual(["foo", "bar", "baz", "qux"]);
  });
});

describe("getValue()", () => {
  it("should return null when there's no value that matches the provided key in the enum.", () => {
    expect(Enum.getValue(IntEnum, "Sixteen" as any)).toBeNull();
    expect(Enum.getValue(StringEnum, "Quux" as any)).toBeNull();
  });

  it("should return the first value that matches the requested key.", () => {
    expect(Enum.getValue(IntEnum, "Four")).toBe(4);
    expect(Enum.getValue(StringEnum, "Foo")).toBe("foo");
  });
});

describe("hasValue()", () => {
  it("should return whether or not the provided value exists in the enum.", () => {
    expect(Enum.hasValue(IntEnum, 2 as any)).toBe(true);
    expect(Enum.hasValue(StringEnum, "qux" as any)).toBe(true);

    expect(Enum.hasValue(IntEnum, 32 as any)).toBe(false);
    expect(Enum.hasValue(StringEnum, "unknown" as any)).toBe(false);
  });
});

describe("parse()", () => {
  it("should return null when the provided value does not exist in the enum.", () => {
    expect(Enum.parse(IntEnum, 32)).toBeNull();
    expect(Enum.parse(StringEnum, "unknown")).toBeNull();
  });

  it("should return the parsed value of the enum.", () => {
    expect(Enum.parse(IntEnum, 2)).toBe(2);
    expect(Enum.parse(StringEnum, "qux")).toBe("qux");
  });
});

describe("getEntries()", () => {
  it("should return the entries of the enum.", () => {
    expect(Enum.getEntries(IntEnum)).toStrictEqual([
      ["One", 1],
      ["Two", 2],
      ["Four", 4],
      ["Eight", 8],
    ]);

    expect(Enum.getEntries(StringEnum)).toStrictEqual([
      ["Foo", "foo"],
      ["Bar", "bar"],
      ["Baz", "baz"],
      ["Qux", "qux"],
    ]);
  });
});
