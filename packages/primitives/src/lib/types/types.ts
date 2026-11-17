/** Denotes the Abstract Constructor Type of the provided Generic. */
export type AbstractConstructor<T> = abstract new (...args: readonly unknown[]) => T;

/** Denotes the Constructor Type of the provided Generic. */
export type Constructor<T> = new (...args: readonly unknown[]) => T;
