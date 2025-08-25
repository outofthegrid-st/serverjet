import { RuntimeError } from "std-crate";


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

  public static delay(t: number = 750): Promise<void> {
    return new Promise(r => setTimeout(r, t));
  }
}


export class Bin {
  public static u32le(n: number): Uint8Array {
    const buf = new ArrayBuffer(4);
    const dv = new DataView(buf);

    dv.setUint32(0, n >>> 0, true);
    return new Uint8Array(buf);
  }

  public static readU32le(bytes: Uint8Array, offset: number = 0): number {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return dv.getUint32(offset, true);
  }

  public static async randomBytes(len: number = 0x40): Promise<Uint8Array> {
    if(__hasNodeSupport()) {
      const { randomBytes } = await import("node:crypto");
      return randomBytes(len);
    }

    if(
      typeof globalThis.crypto !== "undefined" &&
      typeof globalThis.crypto.getRandomValues === "function"
    ) return globalThis.crypto.getRandomValues(new Uint8Array(len));

    throw new RuntimeError("Unable to find secure crypto lib in current environment");
  }
}


export class Enc {
  // 
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
