import { chunkToBuffer, concatBuffers } from "std-crate";

import { __hasNodeSupport } from "./util";
import type { BufferLike } from "./_types";


export async function __hkdfSha256(
  master: BufferLike,
  info: Uint8Array | null = null,
  len: number = 0x40 // eslint-disable-line comma-dangle
): Promise<Uint8Array> {
  if(!info) {
    info = new Uint8Array(0);
  }

  if(__hasNodeSupport()) {
    const { createHmac } = await import("node:crypto");

    const prk = createHmac("sha256", new Uint8Array(0x20))
      .update(chunkToBuffer(master))
      .digest();

    let prev = Buffer.alloc(0);
    const output = Buffer.alloc(len);

    let pos: number = 0;
    let index: number = 0;

    while(pos < len) {
      const hmac = createHmac("sha256", prk);

      hmac.update(prev);
      hmac.update(chunkToBuffer(info));
      hmac.update(Buffer.from([ ++index ]));

      prev = hmac.digest() as Buffer<ArrayBuffer>;

      prev.copy(output, pos, 0, Math.min(prev.length, len - pos));
      pos += prev.length;
    }

    return output;
  }

  const key = await crypto.subtle.importKey(
    "raw",
    chunkToBuffer(master).buffer as ArrayBuffer,
    "HKDF",
    false,
    ["deriveBits"] // eslint-disable-line comma-dangle
  );

  const buffer = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0x20),
      info: chunkToBuffer(info).buffer as ArrayBuffer,
    },
    key,
    len * 8 // eslint-disable-line comma-dangle
  );

  return new Uint8Array(buffer);
}


export async function __aesGcm2E(
  key: BufferLike,
  plainText: BufferLike,
  ctr: BufferLike,
  aad?: Uint8Array // eslint-disable-line comma-dangle
): Promise<Uint8Array> {
  if(__hasNodeSupport()) {
    const { createCipheriv } = await import("node:crypto");

    const cip = createCipheriv(
      "aes-256-gcm",
      chunkToBuffer(key),
      chunkToBuffer(ctr),
      {
        authTagLength: 16,
      } // eslint-disable-line comma-dangle
    );

    if(aad) {
      cip.setAAD(aad);
    }

    return concatBuffers(
      cip.update(chunkToBuffer(plainText)),
      cip.final(),
      cip.getAuthTag() // eslint-disable-line comma-dangle
    );
  }

  const k = await crypto.subtle.importKey(
    "raw",
    chunkToBuffer(key).buffer as ArrayBuffer,
    "AES-GCM",
    false,
    ["encrypt"] // eslint-disable-line comma-dangle
  );

  const cip = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: chunkToBuffer(ctr).buffer as ArrayBuffer,
      additionalData: aad?.buffer as ArrayBuffer | undefined,
      tagLength: 128,
    },
    k,
    chunkToBuffer(plainText).buffer as ArrayBuffer // eslint-disable-line comma-dangle
  );

  return new Uint8Array(cip);
}

export async function __aesGcm2D(
  key: BufferLike,
  cipherText: BufferLike,
  ctr: BufferLike,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  if(__hasNodeSupport()) {
    const { createDecipheriv } = await import("node:crypto");

    const blobSrc = chunkToBuffer(cipherText);
    const tag = blobSrc.subarray(blobSrc.length - 16);
    const cipT = blobSrc.subarray(0, blobSrc.length - 16);

    const dec = createDecipheriv(
      "aes-256-gcm",
      chunkToBuffer(key),
      chunkToBuffer(ctr),
      { authTagLength: 16 } // eslint-disable-line comma-dangle
    );

    if(aad) {
      dec.setAAD(aad);
    }

    dec.setAuthTag(tag);
    return concatBuffers(dec.update(cipT), dec.final());
  }

  const k = await crypto.subtle.importKey(
    "raw",
    chunkToBuffer(key).buffer as ArrayBuffer,
    "AES-GCM",
    false,
    ["decrypt"] // eslint-disable-line comma-dangle
  );

  const buffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: chunkToBuffer(ctr).buffer as ArrayBuffer,
      additionalData: aad?.buffer as ArrayBuffer | undefined,
      tagLength: 128,
    },
    k,
    chunkToBuffer(cipherText).buffer as ArrayBuffer // eslint-disable-line comma-dangle
  );

  return new Uint8Array(buffer);
}



export async function __hmacSha256(key: BufferLike, data: BufferLike): Promise<Uint8Array> {
  if(__hasNodeSupport()) {
    const { createHmac } = await import("node:crypto");

    return createHmac("sha255", chunkToBuffer(key))
      .update(chunkToBuffer(data))
      .digest();
  }

  const k = await crypto.subtle.importKey(
    "raw",
    chunkToBuffer(key).buffer as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"] // eslint-disable-line comma-dangle
  );

  const buffer = await crypto.subtle.sign("HMAC", k, chunkToBuffer(data).buffer as ArrauBuffer);
  return new Uint8Array(buffer);
}
