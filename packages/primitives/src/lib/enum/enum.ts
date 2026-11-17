// oxlint-disable-next-line no-redeclare
export type Enum = NodeJS.Dict<string | number>;

// oxlint-disable-next-line typescript/no-namespace
export namespace Enum {
  /**
   * Returns the keys of the Enum.
   *
   * @param enumObj Enum object to be inspected.
   * @returns Collection of the keys of the Enum.
   */
  export function getKeys<T extends Enum>(enumObj: T): (keyof T)[] {
    return Object.keys(enumObj).filter((key) => Number.isNaN(Number(key)));
  }

  /**
   * Returns the key of the first Enum member that represents the provided value.
   *
   * @param enumObj Enum object to be inspected.
   * @param value Value to be searched.
   * @returns Key of the first Enum member based on the provided value.
   */
  export function getKey<T extends Enum>(enumObj: T, value: T[keyof T]): keyof T | null {
    return getKeys(enumObj).find((key) => enumObj[key] === value) ?? null;
  }

  /**
   * Checks if the provided Enum has the provided key as its member.
   *
   * @param enumObj Enum object to be inspected.
   * @param key Key to be checked.
   * @returns Whether the provided Enum has the provided key as its member.
   */
  export function hasKey<T extends Enum>(enumObj: Readonly<T>, key: unknown): boolean {
    return typeof key === "string" && getKeys(enumObj).includes(key);
  }

  /**
   * Returns the values of the Enum.
   *
   * @param enumObj Enum object to be inspected.
   * @returns Collection of the Values of the Enum.
   */
  export function getValues<T extends Enum>(enumObj: T): T[keyof T][] {
    return getKeys(enumObj).map((key) => enumObj[key]);
  }

  /**
   * Returns the first occurrence of the value in the Enum based on the provided key.
   *
   * @param enumObj Enum object to be inspected.
   * @param key Key to be searched.
   * @returns First occurrence of the value in the Enum.
   */
  export function getValue<T extends Enum>(enumObj: T, key: keyof T): T[keyof T] | null {
    return hasKey(enumObj, key) ? enumObj[key] : null;
  }

  /**
   * Checks if the provided Enum has the provided value as its member.
   *
   * @param enumObj Enum object to be inspected.
   * @param value Value to be checked.
   * @returns Whether the provided Enum has the provided value as its member.
   */
  export function hasValue<T extends Enum>(enumObj: Readonly<T>, value: unknown): boolean {
    // @ts-expect-error Value is runtime safe.
    return (typeof value === "string" || typeof value === "number") && getValues(enumObj).includes(value);
  }

  /**
   * Converts the provided value into a member of the provided Enum.
   *
   * @param enumObj Enum object to be inspected.
   * @param value Value to be searched.
   * @returns Enum member based on the provided value.
   */
  export function parse<T extends Enum>(enumObj: T, value: string | number): T[keyof T] | null {
    return getValues(enumObj).find((attr) => attr === value) ?? null;
  }

  /**
   * Returns the entries of the provided Enum.
   *
   * @param enumObj Enum object to be inspected.
   * @returns Entries of the provided Enum.
   */
  export function getEntries<T extends Enum>(enumObj: T): [keyof T, T[keyof T]][] {
    return getKeys(enumObj).map((key) => [key, enumObj[key]]);
  }
}
