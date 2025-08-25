import {
  CancelableWithToken,
  CancellationToken,
  CancellationTokenSource,
  ICancellationToken,
  RuntimeError,
} from "std-crate";

import { Async } from "./util";
import type { HttpHeaders, HttpMethod } from "./_types";


export interface RemoteTimeQueryOptions extends CancelableWithToken {
  url: string | globalThis.URL;
  interval?: number;
  method?: HttpMethod;
  headers?: HttpHeaders;
  backoffFactor?: number;
  jitter?: number;
  maxBackoff?: number;
  timeout?: number;
  maxRetries?: number;
  fetchOptions?: RequestInit;
  parser?: (ans: unknown) => number;
}


export class ServerTime {
  public static async schedule(
    options: RemoteTimeQueryOptions,
    callback: (timestamp: number) => unknown // eslint-disable-line comma-dangle
  ): Promise<{ cancel(): void }> {
    options.interval ??= 2000;
    const tIt = options.interval > 0 ? options.interval : null;

    const ins = new ServerTime(options.url, options);

    if(tIt == null) {
      const ts = await ins.query();
      ins.cancel();

      callback(ts);
      return { cancel() { } };
    }

    const tId = setInterval(async () => {
      try {
        const ts = await ins.query();
        callback(ts);
        // eslint-disable-next-line no-empty
      } catch { }
    }, tIt);

    ins.token.onCancellationRequested(() => {
      clearInterval(tId);
    });

    return ins;
  }

  #o: RemoteTimeQueryOptions;
  #source: CancellationTokenSource;

  public constructor(url: string | URL, options?: Omit<RemoteTimeQueryOptions, "url">) {
    this.#o = {
      method: "GET",
      backoffFactor: 2,
      maxBackoff: 60000,
      interval: 2000,
      jitter: 0.2,
      maxRetries: 4,
      timeout: 0,
      token: CancellationToken.None,
      ...options,
      url,
    };

    this.#source = new CancellationTokenSource(options?.token);
  }

  public get token(): ICancellationToken {
    return this.#source.token;
  }

  public async query(): Promise<number> {
    const {
      url,
      method = "GET",
      headers,
      timeout = 0,
      maxRetries = 4,
      backoffFactor = 2,
      jitter = 0.2,
      maxBackoff = 60000,
      fetchOptions,
      parser,
    } = this.#o;

    const token = this.#source.token;

    let attempt: number = 0;
    let delay = this.#o.interval ?? 2000;

    // eslint-disable-next-line no-constant-condition
    while(true) {
      if(token.isCancellationRequested) {
        throw new RuntimeError("[ServerTime] remote global time query was cancelled by token");
      }

      try {
        const ac = new AbortController();
        token.onCancellationRequested(ac.abort.bind(ac));

        const tId = timeout > 0 ? setTimeout(ac.abort.bind(ac), timeout) : null;

        const res = await fetch(url, {
          ...fetchOptions,
          method,
          signal: ac.signal,
          headers: this.#ParseHeaders(headers),
        });

        if(tId != null) {
          clearTimeout(tId);
        }

        if((res.status / 100 | 0) !== 2) {
          throw new RuntimeError(`[ServerTime] request failed with status ${res.status}`);
        }

        let raw: unknown = null;

        if(res.headers.get("content-type")?.startsWith("text/plain")) {
          const text = await res.text();

          if(!/^[0-9]+$/.test(text)) {
            throw new RuntimeError("[ServerTime] server didn't answered with a valid UNIX timestamp");
          }

          raw = text;
        }

        if(res.headers.get("content-type")?.startsWith("application/json")) {
          raw = await res.json();
        }

        if(token.isCancellationRequested) {
          throw new RuntimeError("[ServerTime] remote global time query was cancelled by token");
        }

        const timestamp = parser ? parser(raw) : Date.parse(String(raw));

        if(isNaN(timestamp)) {
          throw new RuntimeError("[ServerTime] server answered with a invalid timestamp");
        }

        return timestamp;
      } catch (err: any) {
        if(token.isCancellationRequested) {
          throw new RuntimeError("[ServerTime] remote global time query was cancelled by token");
        }

        if(attempt >= maxRetries) {
          let e = err;

          if(!(err instanceof RuntimeError)) {
            e = new RuntimeError(err.message || String(err));
          }

          throw e;
        }

        const jitterOffset = jitter * delay * (Math.random() - 0.5) * 2;
        const nextDelay = Math.min(maxBackoff, delay * backoffFactor + jitterOffset);

        await Async.delay(nextDelay);
      
        delay = nextDelay;
        attempt++;
      }
    }
  }

  public cancel(): void {
    this.#source.cancel();
  }

  #ParseHeaders(h?: HttpHeaders | [string, string | string[] | undefined][] | Headers): Headers | undefined {
    if(!h)
      return void 0;

    if(h instanceof Headers)
      return h;

    const r = new Headers();

    if(!Array.isArray(h)) {
      h = Object.entries(h);
    }

    for(let i = 0; i < h.length; i++) {
      const v = (Array.isArray(h[i][1]) ? h[i][1] : [h[i][1]]) as string[];
      if(!v) continue;

      for(let j = 0; j < v.length; j++) {
        if(!v[j]) continue;
        r.append(h[i][0], v[j]);
      }
    }

    return r;
  }
}
