"use strict";

/**
 * Hardened HTTP client used by every module:
 *  - SSRF-safe (validates each URL AND every redirect hop)
 *  - per-request AbortController timeout + caller deadline support
 *  - manual redirect following so we can re-validate each hop
 *  - tiny cookie jar so Cloudflare clearance cookies (cf_clearance etc.)
 *    survive across requests to the same host
 *  - realistic browser headers (needed for most video hosts / CDNs)
 */

const { validateUrl } = require("./safety");
const config = require("./config");

class HttpError extends Error {
  constructor(message, statusCode = 502, extra = {}) {
    super(message);
    this.name = "HttpError";
    this.statusCode = statusCode;
    Object.assign(this, extra);
  }
}

/** Per-host cookie jar. Keyed by hostname so cookies never leak cross-site. */
class CookieJar {
  constructor() {
    this.store = new Map(); // host -> Map<name, value>
  }

  ingest(setCookieHeaders, url) {
    const host = url.hostname;
    if (!this.store.has(host)) this.store.set(host, new Map());
    const bucket = this.store.get(host);

    for (const line of setCookieHeaders) {
      const [pair, ...attrs] = line.split(";");
      const eq = pair.indexOf("=");
      if (eq === -1) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (!name) continue;

      const maxAge = attrs
        .map((a) => a.trim().toLowerCase())
        .find((a) => a.startsWith("max-age="));
      if (maxAge && Number(maxAge.split("=")[1]) === 0) {
        bucket.delete(name);
        continue;
      }
      bucket.set(name, value);
    }
  }

  headerFor(url) {
    const bucket = this.store.get(url.hostname);
    if (!bucket || bucket.size === 0) return null;
    return [...bucket.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }
}

function browserHeaders(url, extra = {}) {
  return {
    "User-Agent": config.userAgent,
    Accept:
      "text/html,application/xhtml+xml,application/xml;q=0.9," +
      "application/vnd.apple.mpegurl,application/dash+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    Referer: `${url.protocol}//${url.host}/`,
    ...extra,
  };
}

/**
 * Fetch a URL with redirects manually followed & re-validated.
 * Returns { response, url } — the caller owns the body stream.
 */
async function safeFetch(input, options = {}) {
  const {
    jar = new CookieJar(),
    headers = {},
    method = "GET",
    deadlineAt = Infinity,
    maxRedirects = config.maxRedirects,
    allowPrivate = false,
  } = options;

  let url = allowPrivate ? new URL(String(input)) : await validateUrl(input);
  const visited = [];

  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (Date.now() > deadlineAt) {
      throw new HttpError("Sniff budget exhausted before fetch completed.", 504);
    }

    const controller = new AbortController();
    const remaining = Math.max(1_000, Math.min(config.timeoutMs, deadlineAt - Date.now()));
    const timer = setTimeout(() => controller.abort(), remaining);

    const cookieHeader = jar.headerFor(url);
    const requestHeaders = browserHeaders(url, {
      ...headers,
      ...(cookieHeader ? { Cookie: cookieHeader } : {}),
    });

    let response;
    try {
      response = await fetch(url, {
        method,
        redirect: "manual",
        signal: controller.signal,
        headers: requestHeaders,
      });
    } catch (error) {
      clearTimeout(timer);
      if (error.name === "AbortError") {
        throw new HttpError(`The target server timed out (${url.hostname}).`, 504);
      }
      throw new HttpError(`Unable to fetch ${url.href}: ${error.message}`, 502);
    }
    clearTimeout(timer);

    // Feed any Set-Cookie (cf_clearance, session tokens...) into the jar.
    const setCookies = typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : [];
    if (setCookies.length) jar.ingest(setCookies, url);

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      await response.body?.cancel().catch(() => {});
      if (!location) throw new HttpError("Redirect had no destination.", 502);
      if (hop === maxRedirects) throw new HttpError("Too many redirects.", 502);

      const nextRaw = new URL(location, url).href;
      visited.push(url.href);
      if (visited.includes(nextRaw)) throw new HttpError("Redirect loop detected.", 502);

      url = allowPrivate ? new URL(nextRaw) : await validateUrl(nextRaw);
      if (response.status === 303) method = "GET";
      continue;
    }

    return { response, url };
  }

  throw new HttpError("Redirect limit exceeded.", 502);
}

/** Read up to maxBytes of a response body; cancels the rest. */
async function readLimited(response, maxBytes = config.maxBytes) {
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > maxBytes) {
    await response.body?.cancel().catch(() => {});
    throw new HttpError("The response is too large to inspect.", 413);
  }
  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new HttpError("The response exceeded the inspection limit.", 413);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }

  return Buffer.concat(chunks).toString("utf8");
}

module.exports = { safeFetch, readLimited, HttpError, CookieJar, browserHeaders };
