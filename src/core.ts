import { RuntimeError } from "std-crate";


export function __chunkToBuffer(input: unknown): Uint8Array {
  if(typeof input === "string")
    return __getEncoder().encode(input);

  if(typeof Buffer !== "undefined" && !!Buffer && Buffer.isBuffer(input))
    return input;

  if(input instanceof Uint8Array)
    return input;

  if(ArrayBuffer.isView(input))
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);

  if(input instanceof ArrayBuffer || input instanceof SharedArrayBuffer)
    return new Uint8Array(input);

  if(Array.isArray(input) && input.every(x => typeof x === "number"))
    return Uint8Array.from(input);

  throw new RuntimeError(`Cannot cast 'typeof ${typeof input}' to binary u8`, "ERR_INVALID_TYPE");
}


let te: TextEncoder | null = null;

export function __getEncoder(r?: boolean): TextEncoder {
  if(!te || r) {
    te = new TextEncoder();
  }

  return te;
}
