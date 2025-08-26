export * from "tnetlib-client/@internals/_types";


export type BinaryToTextEncoding =
  | "base64"
  | "base64url"
  | "base62"
  | "hex";


export type MaybePromise<T> = T | Promise<T>;
