import {
  BinaryReader,
  BinaryWriter,
  concatBuffers,
  deserialize,
  getDefaultMask,
  isPlainObject,
  maskBuffer,
  RuntimeError,
  serialize,
  timingSafeEqual,
} from "std-crate";

import type { Redis } from "ioredis";

import { __chunkToBuffer } from "./core";
import { __assertType, Bin, Enc } from "./util";
import { __aesGcm2E, __aesGcm2D, __hkdfSha256, __hmacSha256 } from "./crypto";
import type { BinaryToTextEncoding, BufferLike, HttpHeaders, MaybePromise } from "./_types";


type Entry = [string | number | symbol, unknown];

interface NSER {
  readonly mac: Uint8Array;
  readonly cipT: Uint8Array;
  readonly header: Uint8Array;
  readonly nonce: Uint8Array;
}


const magic_ = Uint8Array.from([
  0X53, 0X45, 0X52, 0X56,
  0X45, 0X52, 0X4A, 0X45,
  0X54, 0X30, 0X45, 0X4E,
  0X56, 0X50, 0X4B, 0X54,
]);


export const JET_V1 = "t/v1 (0.jet.alpha)";


export class JetPayload {
  public static object<T extends Record<string | number | symbol, unknown>>(o: T): JetPayload {
    return new JetPayload(Object.entries(o));
  }

  public static literal(value: unknown): JetPayload {
    return new JetPayload([ ["$payload", value] ]);
  }

  public static revive<T = unknown>(i: JetPayload | readonly Entry[]): T {
    const e =(i instanceof JetPayload ? i : new JetPayload(i)).collect();

    if(e.length === 1 && e[0][0] === "$payload")
      return e[0][1] as T;

    return Object.fromEntries(e) as T;
  }

  #entries: Entry[];
  #icState: number;

  public constructor(_entries?: readonly Entry[]) {
    this.#icState = 0;
    this.#entries = _entries && Array.isArray(_entries) ? _entries : [];

    for(let i = 0; i < this.#entries.length; i++) {
      this.#EnsureField(this.#entries[i][0]);
    }
  }

  public get length(): number {
    return this.#entries.length;
  }

  public delete(field: Entry[0]): boolean {
    this.#EnsureField(field);
    let delI: number = -1;

    for(let i = 0; i < this.#entries.length; i++) {
      if(field === this.#entries[i][0]) {
        delI = i;
        break;
      }
    }

    if(delI > -1) {
      this.#entries.splice(delI, 1);
      this.#icState++;
    }

    return delI > -1;
  }

  public append(field: Entry[0], value: Entry[1]): this {
    this.#EnsureField(field);
    
    let e: boolean = false;

    for(let i = 0; i < this.#entries.length; i++) {
      if(field === this.#entries[i][0]) {
        this.#entries[i][1] = value;
        this.#icState++;
        e = true;

        break;
      }
    }

    if(!e) {
      this.#entries.push([field, value]);
      this.#icState++;
    }

    return this;
  }

  public collect(): Entry[] {
    const e = this.#entries;

    this.#entries = [];
    this.#icState++;

    return e;
  }

  public return<T = unknown>(): T {
    const e = this.#entries;
    this.#entries = [];

    if(e.length === 1 && e[0][0] === "$payload")
      return e[0][1] as T;

    return Object.fromEntries(e) as T;
  }

  public keys(): IterableIterator<Entry[0]> {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;
    const iState = self.#icState;

    let index: number = 0;

    const iterator: IterableIterator<Entry[0]> = {
      next(): IteratorResult<Entry[0]> {
        if(iState !== self.#icState) {
          throw new RuntimeError("[JeyPayload] instance got modified during iteration");
        }

        if(index >= self.#entries.length)
          return { done: true, value: void 0 };

        return { done: false, value: self.#entries[index++][0] };
      },

      [Symbol.iterator]() {
        return iterator;
      },
    };

    return iterator;
  }

  public values(): IterableIterator<Entry[1]> {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;
    const iState = self.#icState;

    let index: number = 0;

    const iterator: IterableIterator<Entry[1]> = {
      next(): IteratorResult<Entry[1]> {
        if(iState !== self.#icState) {
          throw new RuntimeError("[JeyPayload] instance got modified during iteration");
        }

        if(index >= self.#entries.length)
          return { done: true, value: void 0 };

        return { done: false, value: self.#entries[index++][1] };
      },

      [Symbol.iterator]() {
        return iterator;
      },
    };

    return iterator;
  }

  public entries(): IterableIterator<Entry> {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;
    const iState = self.#icState;

    let index: number = 0;

    const iterator: IterableIterator<Entry> = {
      next(): IteratorResult<Entry> {
        if(iState !== self.#icState) {
          throw new RuntimeError("[JeyPayload] instance got modified during iteration");
        }

        if(index >= self.#entries.length)
          return { done: true, value: void 0 };

        return { done: false, value: self.#entries[index++] };
      },

      [Symbol.iterator]() {
        return iterator;
      },
    };

    return iterator;
  }

  public [Symbol.iterator]() {
    return this.entries();
  }

  #EnsureField(e: unknown): asserts e is Entry[0] {
    const err = new RuntimeError(`[JetPayload] Invalid field key 'typeof ${typeof e}'`, "ERR_INVALID_TYPE");

    if(!["string", "number", "symbol"].includes(typeof e)) {
      throw err;
    }

    if(typeof e === "string" && e.trim().length === 0) {
      throw err;
    }
  }
}


class JetProtocol {
  public static toBytes(src: unknown): Uint8Array {
    if(!(src instanceof JetPayload)) {
      if(typeof src === "object" && isPlainObject(src)) {
        src = JetPayload.object(src as Record<string, string>);
      } else {
        src = JetPayload.literal(src);
      }
    }

    __assertType<JetPayload>(src);

    const ww = new BinaryWriter();
    serialize(ww, src.collect());

    return ww.drain();
  }

  public static toPayload(bin: BufferLike): JetPayload {
    const r = new BinaryReader(__chunkToBuffer(bin));
    const e = deserialize<readonly Entry[]>(r);

    if(!Array.isArray(e)) {
      throw new RuntimeError("[JetProtocol] malformed binary payload");
    }

    return new JetPayload(e);
  }
}


export interface EnvelopeInit {
  versionId?: string | number;
  secureTransportKey?: BufferLike;
  maskByte?: number | Uint8Array;
  compressionAlgorithm?: number;
  supportIncomingCompression?: number[];
  allowedWindow?: number;
  redisClient?: Redis;
  redisStoragePrefix?: string;
  queryUnixTimestamp?: () => MaybePromise<number>;

  /**
   * ATTENTION!! When true, protocol's did NOT sign or check integrity of packets
   */
  bypassSignature?: boolean;
}

export class JetEnvelope {
  readonly #Protected_: {
    version: string | number;
    // compressionAlgorithm: number;
    maskByte: number | Uint8Array;
    transportKey: Uint8Array | null;
    // supportIncomingCompression: ReadonlySet<number>;
    noSign: boolean | null;
    allowedWindow: number;
    redisClient: Redis | null;
    seenNonces: Map<string, number>;
    storagePrefix: string;
    disposed: boolean;
    currentTimestamp: (() => MaybePromise<number>) | null;
  };

  public constructor(o?: EnvelopeInit) {
    const transportKey = o?.secureTransportKey ? __chunkToBuffer(o.secureTransportKey) : null;

    if(transportKey != null && transportKey.length < 0x40) {
      throw new RuntimeError("[JetProtocol] transport key is too short to ensure a secure transport. Use keys with size >= 64 bytes");
    }

    let allowedWindow = o?.allowedWindow ?? 0x3C;

    if(allowedWindow < 0x01) {
      allowedWindow = 0x3C;
    }
    
    this.#Protected_ = {
      transportKey,
      allowedWindow,
      disposed: false,
      seenNonces: new Map(),
      currentTimestamp: null,
      redisClient: o?.redisClient ?? null,
      noSign: o?.bypassSignature ?? null,
      version: o?.versionId ?? JET_V1,
      maskByte: o?.maskByte ?? getDefaultMask(),
      storagePrefix: o?.redisStoragePrefix || `tsj_${o?.versionId ?? JET_V1}.sns__`,
    };
  }

  public get version(): string | number {
    this.#EnsureNotDisposed();
    return this.#Protected_.version;
  }

  public createOutgoingPacket(payload: unknown): Promise<Uint8Array>;
  public createOutgoingPacket(payload: unknown, enc: BinaryToTextEncoding): Promise<string>;
  public async createOutgoingPacket(
    payload: unknown,
    enc?: BinaryToTextEncoding // eslint-disable-line comma-dangle
  ): Promise<Uint8Array | string> {
    this.#EnsureNotDisposed();
    const ww = new BinaryWriter();

    serialize(ww, magic_);
    serialize(ww, this.#Protected_.version);
    serialize(ww, this.#Protected_.transportKey != null ? 1 : 0);
    serialize(ww, this.#Protected_.noSign === true ? 0 : 1);

    if(this.#Protected_.transportKey != null) {
      const {
        cipT,
        header,
        mac,
        nonce,
      } = (await this.#Encrypt(JetProtocol.toBytes(payload)))!;

      serialize(ww, header);
      serialize(ww, maskBuffer(cipT, this.#Protected_.maskByte));
      serialize(ww, maskBuffer(mac, this.#Protected_.maskByte));
      serialize(ww, maskBuffer(nonce, this.#Protected_.maskByte));
    } else {
      serialize(ww, maskBuffer(JetProtocol.toBytes(payload), this.#Protected_.maskByte));
    }

    const bytes = ww.drain();

    // TODO: handle compression

    if(!enc) return bytes;
    return new Enc(enc).encode(bytes);
  }

  public async unwrapIncomingPacket(
    packet: BufferLike,
    inputEncoding?: BinaryToTextEncoding // eslint-disable-line comma-dangle
  ): Promise<JetPayload> {
    this.#EnsureNotDisposed();

    if(
      typeof packet === "string" &&
      !!inputEncoding &&
      Enc.isBinaryToTextEncoding(inputEncoding)
    ) {
      packet = new Enc(inputEncoding).decode(packet);
    }
    
    const reader = new BinaryReader(__chunkToBuffer(packet));
   
    // TODO: handle decompression

    const mag = deserialize<Uint8Array>(reader);

    /** PACKET VERSION */
    deserialize<string | number>(reader);
    /** PACKET VERSION */

    const encFlag = deserialize<number>(reader);
    const signFlag = deserialize<number>(reader);

    if(!timingSafeEqual(mag, magic_)) {
      throw new RuntimeError("[JetEnvelope] the provided packet does not appear to be a transport envelope", "ERR_INVALID_ARGUMENT");
    }

    if(encFlag === 1) {
      if(!this.#Protected_.transportKey) {
        throw new RuntimeError("[JetEnvelope] failed to unwrap incoming packet: no transport key configured");
      }

      const header = deserialize<Uint8Array>(reader);
      const cipT = maskBuffer(deserialize<Uint8Array>(reader), this.#Protected_.maskByte);
      const mac = maskBuffer(deserialize<Uint8Array>(reader), this.#Protected_.maskByte);
      const nonce = maskBuffer(deserialize<Uint8Array>(reader), this.#Protected_.maskByte);

      const now = await this.#CheckTimestampWindow(header);
      await this.#CheckNonceReplay(nonce, now);

      const dmk = await __hkdfSha256(this.#Protected_.transportKey);
      const ek = dmk.subarray(0, 0x20);
      const sk = dmk.subarray(0x20, 0x40);

      if(signFlag === 1) {
        const macF = await __hmacSha256(sk, concatBuffers(header, nonce, cipT));
        const mac16 = macF.subarray(0, 0x10);

        if(!timingSafeEqual(mac16, mac)) {
          throw new RuntimeError("[JetEnvelope] failed to check integrity of incoming packet", "ERR_INVALID_SIGNATURE");
        }
      }

      const plain = await __aesGcm2D(ek, cipT, nonce, header);
      return JetProtocol.toPayload(plain);
    }

    const bytes = maskBuffer(deserialize<Uint8Array>(reader), this.#Protected_.maskByte);
    return JetProtocol.toPayload(bytes);
  }

  public headers(): HttpHeaders {
    return {
      "X-Jet-Version": String(this.#Protected_.version).trim(),
      "X-Jet-Compression-Flag": "-0x00",
      "X-Jet-Transfer-Encoding": "<enc>",
    };
  }

  public dispose(): void {
    if(!this.#Protected_.disposed) {
      this.#Protected_.disposed = true;

      this.#Protected_.seenNonces.clear();
      this.#Protected_.transportKey = null;
      this.#Protected_.redisClient = null;
      this.#Protected_.maskByte = null!;
    }
  }

  async #Encrypt(src: BufferLike, kv: number = 1, hkdfInfo?: Uint8Array): Promise<NSER | null> {
    this.#EnsureNotDisposed();

    if(!this.#Protected_.transportKey)
      return null;

    const nonce = await Bin.randomBytes(0xC);
    const ts = await this.#GetTimestamp();

    const dmk = await __hkdfSha256(this.#Protected_.transportKey, hkdfInfo);
    const header = new Uint8Array(0x06);

    header[0] = kv;

    const view = new DataView(header.buffer);
    view.setUint32(1, ts >>> 0);
    view.setUint8(5, ts & 0xFF);

    const ek = dmk.subarray(0, 0x20);
    const sk = dmk.subarray(0x20, 0x40);

    const cipT = await __aesGcm2E(ek, src, nonce, header);

    const macF = await __hmacSha256(sk, concatBuffers(
      header,
      nonce,
      cipT // eslint-disable-line comma-dangle
    ));

    return {
      cipT,
      header,
      nonce,
      mac: macF.subarray(0, 0x10),
    };
  }

  async #CheckNonceReplay(nonce: Uint8Array, now: number): Promise<void> {
    this.#EnsureNotDisposed();
    const key = Enc.encodeHex(nonce);

    if(this.#Protected_.redisClient != null) {
      const exists = await this.#Protected_.redisClient.exists(key);

      if(exists) {
        throw new RuntimeError("[JetEnvelope] packet nonce refused due to replay attack protection");
      }

      await this.#Protected_.redisClient.set(
        key, "1",
        "EX", this.#Protected_.allowedWindow * 2,
        "NX" // eslint-disable-line comma-dangle
      );
    } else {
      for(const [n, t] of this.#Protected_.seenNonces.entries()) {
        if(now - t > this.#Protected_.allowedWindow * 2) {
          this.#Protected_.seenNonces.delete(n);
        }
      }

      if(this.#Protected_.seenNonces.has(key)) {
        throw new RuntimeError("[JetEnvelope] packet nonce refused due to replay attack protection");
      }

      this.#Protected_.seenNonces.set(key, now);
    }
  }

  async #CheckTimestampWindow(header: Uint8Array): Promise<number> {
    this.#EnsureNotDisposed();
    const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
    
    const ts = view.getUint32(1, false);
    const now = await this.#GetTimestamp();

    if(Math.abs(now - ts) > this.#Protected_.allowedWindow) {
      throw new RuntimeError(`[JetEnvelope] packet window was expired t-${Math.abs(now - ts)}`);
    }

    return now;
  }

  async #GetTimestamp(): Promise<number> {
    this.#EnsureNotDisposed();

    if(typeof this.#Protected_.currentTimestamp === "function") {
      const ts = await this.#Protected_.currentTimestamp();

      if(typeof ts !== "number" || Number.isNaN(ts))
        return Math.floor(Date.now() / 0x3E8);

      return ts;
    }

    return Math.floor(Date.now() / 0x3E8);
  }

  #EnsureNotDisposed(): void {
    if(this.#Protected_.disposed) {
      throw new RuntimeError("[JetEnvelope] this instance is already disposed", "ERR_RESOURCE_DISPOSED");
    }
  }
}

export default JetProtocol;
