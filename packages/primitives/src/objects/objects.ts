// oxlint-disable-next-line typescript/no-namespace
export namespace Objects {
  /**
   * Checks if the provided data is a Plain Javascript Object.
   *
   * @param data Object to be checked.
   * @returns The provided data is a Plain Javascript Object.
   */
  export function isPlain(data: unknown): data is object {
    if (typeof data !== "object" || data === null) {
      return false;
    }

    const proto = Object.getPrototypeOf(data) as object | null;

    return proto === null || proto === Object.prototype || Object.getPrototypeOf(proto) === null;
  }

  /**
   * Removes null and undefined values from the properties of an object or an array of objects. This method mutates the
   * provided object in-place.
   *
   * @param data Object or array of objects to be cleansed.
   * @returns Provided object without null and undefined properties.
   */
  export function removeNullishValues<T = unknown>(data: T): T {
    if (typeof data !== "object" || data === null) {
      return data;
    }

    for (let [key, value] of Object.entries(data)) {
      if (value == null) {
        Reflect.deleteProperty(data, key);
        continue;
      }

      if (Array.isArray(value)) {
        // oxlint-disable-next-line typescript/no-unsafe-return
        value = value.filter((v) => v != null).map((v) => removeNullishValues(v));
        Reflect.set(data, key, value);
        continue;
      }

      if (typeof value === "object") {
        removeNullishValues(value);
        Reflect.set(data, key, value);
        continue;
      }
    }

    return data;
  }
}
