import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { Objects } from "./objects.ts";

const invalidPlainObjects: any[] = [
  undefined,
  null,
  true,
  1,
  1.2,
  1n,
  "a",
  Symbol("a"),
  Buffer,
  Buffer.alloc(1),
  () => 1,
  [],
];

describe("isPlain()", () => {
  it.each(invalidPlainObjects)("should return false when the data is not a plain javascript object.", (data) => {
    expect(Objects.isPlain(data)).toBe(false);
  });

  it.each([{}, Object.create(null), Object.create(Object.create(null))])(
    "should return true when the data is a plain javascript object.",
    (data) => {
      expect(Objects.isPlain(data)).toBe(true);
    },
  );
});

describe("removeNullishValues()", () => {
  it("should remove all undefined values from an object.", () => {
    const data: object[] = [
      {
        address: { owner: undefined, referencePoint: null, streetAddress: "123 1st Avenue", trees: ["Oak", null] },
        age: 23,
        hobbies: ["Jogging", undefined, { name: "Gambling", skills: ["Poker", "Black Jack"] }],
        name: "John Doe",
        occupation: null,
        vehicle: undefined,
      },
    ];

    expect(() => Objects.removeNullishValues(data)).not.toThrow();

    expect(data).toStrictEqual<object[]>([
      {
        address: { streetAddress: "123 1st Avenue", trees: ["Oak"] },
        age: 23,
        hobbies: ["Jogging", { name: "Gambling", skills: ["Poker", "Black Jack"] }],
        name: "John Doe",
      },
    ]);
  });
});
