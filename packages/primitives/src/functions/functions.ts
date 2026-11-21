import type { AbstractConstructor, Constructor } from "../types/types.ts";

// oxlint-disable-next-line typescript/no-namespace
export namespace Functions {
  export function isClass<T>(data: unknown): data is AbstractConstructor<T> | Constructor<T> {
    return typeof data === "function" && "prototype" in data;
  }
}
