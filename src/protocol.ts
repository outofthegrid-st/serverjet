import {
  BinaryReader,
  BinaryWriter,
  type BufferLike,
  chunkToBuffer,
  concatBuffers,
  deserialize,
  getDefaultMask,
  isPlainObject,
  maskBuffer,
  RuntimeError,
  serialize,
} from "std-crate";

import {
  type BinaryToTextEncoding,
  type HttpHeaders,
  IterableWithKey,
} from "./_types";

import { __assertType, Bin } from "./util";
import { Z_AGID_IDENTITY } from "./z";
import { __aesGcm2E, __hkdfSha256, __hmacSha256 } from "./core";


type Entry = [string | number | symbol, unknown];

interface NSER {
  readonly mac: Uint8Array;
  readonly cipT: Uint8Array;
  readonly header: Uint8Array;
  readonly nonce: Uint8Array;
}


const magic_ = Uint8Array.from([
  // 
]);


export const JET_V1 = "t/v1 (0.jet.alpha)";


export class JetPayload implements IterableWithKey<Entry[0], Entry[1]> {
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


export interface ProtocolInit {
  versionId?: string | number;
  secureTransportKey?: BufferLike;
  maskByte?: number | Uint8Array;
  compressionAlgorithm?: number;
  supportIncomingCompression?: number[];
  transportKey: Uint8Array | null;

  /**
   * ATTENTION!! When true, protocol's did NOT sign or check integrity of packets
   */
  bypassSignature?: boolean;
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
    const r = new BinaryReader(chunkToBuffer(bin));
    const e = deserialize<readonly Entry[]>(r);

    if(!Array.isArray(e)) {
      throw new RuntimeError("[JetProtocol] malformed binary payload");
    }

    return new JetPayload(e);
  }

  readonly #Protected_: {
    version: string | number;
    compressionAlgorithm: number;
    maskByte: number | Uint8Array;
    transportKey: Uint8Array | null;
    supportIncomingCompression: ReadonlySet<number>;
    noSign?: boolean;
    currentTimestamp: number | null;
  };

  public constructor(o?: ProtocolInit) {
    const supportIncomingCompression = [ o?.compressionAlgorithm ?? Z_AGID_IDENTITY ];

    if(o?.supportIncomingCompression && Array.isArray(o.supportIncomingCompression)) {
      supportIncomingCompression.push(...o.supportIncomingCompression);
    }

    const transportKey = o?.secureTransportKey ? chunkToBuffer(o.secureTransportKey) : null;

    if(transportKey != null && transportKey.length < 0x40) {
      throw new RuntimeError("[JetProtocol] transport key is too short to ensure a secure transport. Use keys with size >= 64 bytes");
    }
    
    this.#Protected_ = {
      transportKey,
      noSign: o?.bypassSignature,
      version: o?.versionId ?? JET_V1,
      maskByte: o?.maskByte ?? getDefaultMask(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      compressionAlgorithm: o?.compressionAlgorithm ?? Z_AGID_IDENTITY,
      supportIncomingCompression: new Set(supportIncomingCompression),
    };
  }

  public get version(): string | number {
    return this.#Protected_.version;
  }

  public createOutgoingPacket(payload: unknown): Promise<Uint8Array>;
  public createOutgoingPacket(payload: unknown, enc: BinaryToTextEncoding): Promise<string>;
  public async createOutgoingPacket(
    payload: unknown,
    enc?: BinaryToTextEncoding // eslint-disable-line comma-dangle
  ): Promise<Uint8Array | string> {
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
    if(!enc) return bytes;
    // TODO: encoding !!
  }

  public async unwrapIncomingPacket<T = unknown>(
    pkt: BufferLike,
    inputEncoding?: BinaryToTextEncoding // eslint-disable-line comma-dangle
  ): Promise<T> {
    // TODO: unwrap packet
  }

  public outgoingHeaders(): HttpHeaders {
    return {
      "X-Jet-Version": String(this.#Protected_.version).trim(),
      "X-Jet-Compression-Flag": this.#Protected_.compressionAlgorithm.toString(),
      // TODO: the rest of necessary headers
    };
  }

  async #Encrypt(src: BufferLike, kv: number = 1, hkdfInfo?: Uint8Array): Promise<NSER | null> {
    if(!this.#Protected_.transportKey)
      return null;

    const nonce = await Bin.randomBytes(0xC);
    const ts = this.#Protected_.currentTimestamp ?? Math.floor(Date.now() / 1000);

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
}

export default JetProtocol;
