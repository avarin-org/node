// oxlint-disable-next-line no-redeclare
export type JSON =
  | string
  | number
  | boolean
  | NodeJS.Dict<JSON>
  | { toJSON: (...args: readonly unknown[]) => JSON }
  | JSON[]
  | null;

// oxlint-disable-next-line typescript/no-namespace
export namespace JSON {
  /**
   * JSON Reviver function that prevents prototype and constructor pollution.
   *
   * @param key JSON object key.
   * @param value JSON object value.
   * @param reviver Reviver function that transforms the results.
   * @returns Parsed object without forbidden properties.
   */
  function stripForbiddenProperties<T extends JSON>(
    key: string,
    value: T[keyof T],
    reviver?: (this: unknown, key: string, value: T[keyof T]) => T[keyof T],
  ): T[keyof T] | undefined {
    if (key === "__proto__" || key === "constructor") {
      return;
    }

    return typeof reviver === "function" ? reviver(key, value) : value;
  }

  /**
   * Converts a JavaScript Object Notation (JSON) string into an object.
   *
   * @param text A valid JSON string.
   * @param reviver A function that transforms the results. This function is called for each member of the object. If a
   *   member contains nested objects, the nested objects are transformed before the parent object is.
   * @returns Parsed object from the JSON string.
   */
  export function parse<T extends JSON>(
    text: string,
    reviver?: (this: unknown, key: string, value: T[keyof T]) => T[keyof T],
  ): T {
    return globalThis.JSON.parse(text, (key, value: T[keyof T]) =>
      stripForbiddenProperties<T>(key, value, reviver),
    ) as T;
  }

  /**
   * Converts a JavaScript value to a JavaScript Object Notation (JSON) string.
   *
   * @param value A JavaScript value, usually an object or array, to be converted.
   * @param replacer A function that transforms the results or an array of strings and numbers that acts as an approved
   *   list for selecting the object properties that will be stringified.
   * @param space Adds indentation, white space, and line break characters to the return-value JSON text to make it
   *   easier to read.
   * @returns Stringified object.
   */
  export function stringify<T extends JSON>(
    value: T,
    replacer?: (this: unknown, key: string, value: T[keyof T]) => T | ((number | string)[] | null),
    space?: string | number,
  ): string {
    return globalThis.JSON.stringify(value, replacer, space);
  }
}
