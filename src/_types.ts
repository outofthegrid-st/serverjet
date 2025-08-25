export * from "tnetlib-client/@internals/_types";


export type BinaryToTextEncoding = "base64" | "base64url" | "hex" | "binary";

export type MaybePromise<T> = T | Promise<T>;

export type MaybeArray<T> = T | T[];


export interface IterableWithKey<TKey = unknown, TValue = unknown> {
  keys(): IterableIterator<TKey>;
  values(): IterableIterator<TValue>;
  entries(): IterableIterator<readonly [TKey, TValue]>;

  [Symbol.iterator](): IterableIterator<readonly [TKey, TValue]>;
}
