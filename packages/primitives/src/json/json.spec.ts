import { Buffer } from "node:buffer";

import { describe, expect, it } from "vitest";

import { JSON } from "./json.ts";

describe("parse()", () => {
  it("should parse a safe json object as usual.", () => {
    interface Type {
      foo: string;
      baz: number;
      [x: string]: JSON;
    }

    expect(JSON.parse<Type>('{"foo":"bar","baz":123}')).toStrictEqual<Type>({ baz: 123, foo: "bar" });

    expect(
      // oxlint-disable-next-line vitest/no-conditional-in-test
      JSON.parse<Type>('{"foo":"bar","baz":123}', (_, value) => (typeof value === "number" ? value * 2 : value)),
    ).toStrictEqual<Type>({ baz: 246, foo: "bar" });
  });

  it('should remove the forbidden keys "__proto__" and "constructor" from the parsed object.', () => {
    expect(
      JSON.parse(
        '{"foo":"bar","__proto__":{"admin":true},"constructor":{"prototype":{"admin":true}},"x":{"p":"key","__proto__":{"admin":true},"constructor":{"prototype":{"admin":true}}}}',
      ),
    ).toStrictEqual({
      foo: "bar",
      x: { p: "key" },
    });
  });
});

describe("stringify()", () => {
  it("should stringify a javascript object into a json object as usual.", () => {
    expect(JSON.stringify({ baz: 123, buf: Buffer.alloc(1), foo: "bar" })).toBe(
      '{"baz":123,"buf":{"type":"Buffer","data":[0]},"foo":"bar"}',
    );
  });
});
