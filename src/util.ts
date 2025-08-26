import { RuntimeError } from "std-crate";

import { __chunkToBuffer } from "./core";
import type { BinaryToTextEncoding, BufferLike, Dict } from "./_types";


export class Async {
  public static withAsyncBody<T, E = Error>(
    bodyFn: (
      resolve: (value: T) => unknown,
      reject: (error: E) => unknown
    ) => Promise<unknown> // eslint-disable-line comma-dangle
  ): Promise<T> {
    // eslint-disable-next-line no-async-promise-executor
    return new Promise<T>(async (resolve, reject) => {
      try {
        await bodyFn(resolve, reject);
      } catch (error: unknown) {
        reject(error);
      }
    });
  }

  public static delay(t: number = 0x2EE): Promise<void> {
    return new Promise(r => setTimeout(r, t));
  }
}


export class Bin {
  public static u32le(n: number): Uint8Array {
    const buf = new ArrayBuffer(0x04);
    const dv = new DataView(buf);

    dv.setUint32(0, n >>> 0, true);
    return new Uint8Array(buf);
  }

  public static readU32le(bytes: Uint8Array, offset: number = 0x00): number {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return dv.getUint32(offset, true);
  }

  public static async randomBytes(len: number = 0x40): Promise<Uint8Array> {
    let result: Uint8Array | null = null;

    if(__hasNodeSupport()) {
      const { randomBytes } = await import("node:crypto");
      result = randomBytes(len);
    } else if(
      typeof globalThis !== "undefined" &&
      typeof globalThis.crypto.getRandomValues === "function"
    ) {
      result = new Uint8Array(len);
      globalThis.crypto.getRandomValues(result);
    }

    if(!result) {
      throw new RuntimeError("Unable to find secure crypto lib in current environment");
    }

    return result;
  }
}


export class Enc {
  static #BASE62_ALPHABET: string = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  public static encodeBase64(bytes: BufferLike): string {
    const u8 = __chunkToBuffer(bytes);

    if(__hasNodeSupport() || typeof globalThis.Buffer !== "undefined" && !!globalThis.Buffer)
      return globalThis.Buffer.from(u8).toString("base64");

    let result: string = "";
    const chunkSize: number = 0x8000;

    for(let i = 0; i < u8.length; i += chunkSize) {
      const chunk = u8.subarray(i, i + chunkSize);
      result += String.fromCharCode.apply(null, Array.from(chunk));
    }

    return btoa(result);
  }

  public static decodeBase64(str: string): Uint8Array {
    // Type `Buffer` extends native `Uint8Array`
    // so isn't necessary to cast result to u8
    if(__hasNodeSupport() || typeof globalThis.Buffer !== "undefined" && !!globalThis.Buffer)
      return globalThis.Buffer.from(str, "base64");

    const bin = atob(str);
    const out = new Uint8Array(bin.length);

    for(let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }

    return out;
  }

  public static encodeBase64url(bytes: BufferLike): string {
    return Enc.encodeBase64(bytes)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  public static decodeBase64url(str: string): Uint8Array {
    let s = str.replace(/-/g, "+").replace(/_/g, "/");

    while(s.length % 0x04 !== 0) {
      s += "=";
    }

    return Enc.decodeBase64(s);
  }

  public static encodeHex(bytes: BufferLike): string {
    const u8 = __chunkToBuffer(bytes);

    if(__hasNodeSupport() || typeof globalThis.Buffer !== "undefined" && !!globalThis.Buffer)
      return globalThis.Buffer.from(u8).toString("base64");

    return Array.from(u8)
      .map(b => b.toString(0x10).padStart(0x02, "0"))
      .join("");
  }

  public static decodeHex(str: string): Uint8Array {
    // Type `Buffer` extends native `Uint8Array`
    // so isn't necessary to cast result to u8
    if(__hasNodeSupport() || typeof globalThis.Buffer !== "undefined" && !!globalThis.Buffer)
      return globalThis.Buffer.from(str, "hex");

    if(str.length % 0x02 !== 0) {
      throw new RuntimeError("The provided hex string is invalid or malformed");
    }

    const out = new Uint8Array(str.length / 0x02);

    for(let i = 0; i < out.length; i++) {
      const si = i * 0x02;
      out[i] = parseInt(str.slice(si, si + 0x02), 0x10);
    }

    return out;
  }

  public static encodeBase62(bytes: BufferLike): string {
    const u8 = __chunkToBuffer(bytes);

    if(u8.length === 0)
      return "";

    const digits = [0];

    for(let i = 0; i < u8.length; i++) {
      let carry = u8[i];

      for(let j = 0; j < digits.length; j++) {
        const val = digits[j] * 0x100 + carry;

        digits[j] = val % 0x3E;
        carry = Math.floor(val / 0x3E);
      }

      while(carry > 0) {
        digits.push(carry % 0x3E);
        carry = Math.floor(carry / 0x3E);
      }
    }

    let out: string = "";

    for(let k = 0; k < u8.length && u8[k] === 0; k++) {
      out += Enc.#BASE62_ALPHABET[0];
    }

    for(let q = digits.length - 0x01; q >= 0; q--) {
      out += Enc.#BASE62_ALPHABET[digits[q]];
    }

    return out;
  }

  public static decodeBase62(str: string): Uint8Array {
    if(str.length === 0)
      return new Uint8Array(0);

    const A = Enc.#BASE62_ALPHABET;
    const map: Dict<number> = {};

    for(let i = 0; i < A.length; i++) {
      map[A[i]] = i;
    }

    const bytes: number[] = [0];

    for(let i = 0; i < str.length; i++) {
      const ch = str[i];

      if(!(ch in map)) {
        throw new RuntimeError(`Invalid base62 character "${ch}"`, "ERR_INVALID_ARGUMENT");
      }

      let carry = map[ch];

      for(let j = 0; j < bytes.length; j++) {
        const val = bytes[j] * 0x3E + carry;

        bytes[j] = val & 0xFF;
        carry = val >> 0x08;
      }

      while(carry > 0) {
        bytes.push(carry & 0xFF);
        carry >>= 0x08;
      }
    }

    let leadingZeros: number = 0;

    for(let i = 0; i < str.length && str[i] === A[0]; i++) {
      leadingZeros++;
    }

    const out = new Uint8Array(leadingZeros + bytes.length);

    for(let i = 0; i < bytes.length; i++) {
      out[out.length - 1 - i] = bytes[i];
    }

    return out;
  }

  public static isBinaryToTextEncoding(str: string): str is BinaryToTextEncoding {
    return [
      "base64",
      "base64url",
      "base62",
      "hex",
    ].includes(str);
  }

  readonly #enc: BinaryToTextEncoding;

  public constructor(enc: BinaryToTextEncoding) {
    if(!Enc.isBinaryToTextEncoding(enc)) {
      throw new RuntimeError(`Invalid binary to text encoding "${enc}"`, "ERR_INVALID_ARGUMENT");
    }

    this.#enc = enc;
  }

  public encode(bytes: BufferLike): string {
    const encoders: Record<BinaryToTextEncoding, (bytes: BufferLike) => string> = {
      base62: Enc.encodeBase62,
      base64: Enc.encodeBase64,
      base64url: Enc.encodeBase64url,
      hex: Enc.encodeHex,
    };

    const c = encoders[this.#enc];

    if(typeof c !== "function") {
      throw new RuntimeError(`Invalid binary to text encoding "${this.#enc}"`, "ERR_INVALID_ARGUMENT");
    }

    return c(bytes);
  }

  public decode(str: string): Uint8Array {
    const encoders: Record<BinaryToTextEncoding, (str: string) => Uint8Array> = {
      base62: Enc.decodeBase62,
      base64: Enc.decodeBase64,
      base64url: Enc.decodeBase64url,
      hex: Enc.decodeHex,
    };

    const c = encoders[this.#enc];

    if(typeof c !== "function") {
      throw new RuntimeError(`Invalid binary to text encoding "${this.#enc}"`, "ERR_INVALID_ARGUMENT");
    }

    return c(str);
  }
}


export function __assertType<T>(arg: unknown): asserts arg is T { void arg; }

export function __hasNodeSupport(): boolean {
  try {
    if(typeof process === "undefined")
      return false;

    require("node:util");
    return true;
  } catch {
    return false;
  }
}
