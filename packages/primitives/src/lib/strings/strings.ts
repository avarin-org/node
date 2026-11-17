// oxlint-disable-next-line typescript/no-namespace
export namespace Strings {
  /**
   * Checks if the provided string is empty.
   *
   * @param str String to be checked.
   * @returns Whether or not the provided string is empty.
   */
  export function isEmpty(str: string): boolean {
    return str.trim() === "";
  }
}
