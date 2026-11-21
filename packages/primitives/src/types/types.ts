/**
 * Denotes the Abstract Constructor Type of the provided Generic.
 */
// oxlint-disable-next-line typescript/no-explicit-any
export type AbstractConstructor<T> = abstract new (...args: readonly any[]) => T;

/**
 * Denotes the Constructor Type of the provided Generic.
 */
// oxlint-disable-next-line typescript/no-explicit-any
export type Constructor<T> = new (...args: readonly any[]) => T;
