
const express = require("express");
const cheerio = require("cheerio");
const ipaddr = require("ipaddr.js");
const dns = require("node:dns").promises;
const net = require("node:net");

const app = express();
app.disable("x-powered-by");

const PORT = Number(process.env.PORT) || 3000;
const MAX_BYTES = 3 * 1024 * 1024;
const TIMEOUT_MS = 10000;
const MAX_REDIRECTS = 5;
const MAX_RESULTS = 100;
const CACHE_TTL_MS = 30_000;

const MEDIA_EXTENSIONS =
  /\.(?:m3u8|mp4|m4v|mkv|webm|mov|avi|mpg|mpeg|ts|m4s|mpd|ogv|ogg|mp3|m4a|aac|wav|flac)(?:$|[?#])/i;

const PLAYLIST_TYPES = [
  "application/vnd.apple.mpegurl",
  "application/x-mpegurl",
  "application/dash+xml"
];

const cache = new Map();
const requests = new Map();

app.use((req, res, next) => {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Referrer-Policy", "no-referrer");
  res.set("X-Frame-Options", "DENY");
  res.set("Cache-Control", "no-store");
  next();
});

// Basic per-IP rate limiting. Use a shared store for multi-instance deployments.
app.use((req, res, next) => {
  const now = Date.now();
  const key = req.ip || "unknown";
  let entry = requests.get(key);

  if (!entry || now - entry.start > 60_000) {
    entry = { start: now, count: 0 };
    requests.set(key, entry);
  }

  entry.count++;
  if (entry.count > 30) {
    return res.status(429).send("Too many requests. Try again shortly.");
  }

  next();
});

function isPublicAddress(address) {
  try {
    const parsed = ipaddr.process(address);
    return parsed.range() === "unicast";
  } catch {
    return false;
  }
}

async function validateUrl(value) {
  let url;

  try {
    url = new URL(value);
  } catch {
    throw new Error("The supplied link is not a valid URL.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS links are supported.");
  }

  if (url.username || url.password) {
    throw new Error("URLs containing credentials are not supported.");
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();

  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname === "metadata.google.internal"
  ) {
    throw new Error("Private and local network hosts are not allowed.");
  }

  if (net.isIP(hostname)) {
    if (!isPublicAddress(hostname)) {
      throw new Error("Private or reserved IP addresses are not allowed.");
    }
  } else {
    let addresses;

    try {
      addresses = await dns.lookup(hostname, { all: true, verbatim: true });
    } catch {
      throw new Error("The target hostname could not be resolved.");
    }

    if (
      !addresses.length ||
      addresses.some((item) => !isPublicAddress(item.address))
    ) {
      throw new Error("The hostname resolves to a private or reserved address.");
    }
  }

  url.hash = "";
  return url;
}

async function safeFetch(input) {
  let url = await validateUrl(input);

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

    let response;

    try {
      response = await fetch(url, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent": "MediaDiscovery/1.0",
          Accept:
            "text/html,application/xhtml+xml,application/json," +
            "application/vnd.apple.mpegurl,application/dash+xml,*/*;q=0.5"
        }
      });
    } catch (error) {
      if (error.name === "AbortError") {
        throw new Error("The target server timed out.");
      }
      throw new Error("Unable to fetch the target URL.");
    } finally {
      clearTimeout(timer);
    }

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      await response.body?.cancel();

      if (!location) throw new Error("Redirect had no destination.");
      if (i === MAX_REDIRECTS) throw new Error("Too many redirects.");

      url = await validateUrl(new URL(location, url).href);
      continue;
    }

    return { response, url };
  }

  throw new Error("Redirect limit exceeded.");
}

async function readLimited(response) {
  const length = Number(response.headers.get("content-length") || 0);

  if (length > MAX_BYTES) {
    await response.body?.cancel();
    throw new Error("The response is too large to inspect.");
  }

  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      size += value.byteLength;
      if (size > MAX_BYTES) {
        await reader.cancel();
        throw new Error("The response exceeded the inspection limit.");
      }

      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }

  return Buffer.concat(chunks).toString("utf8");
}

function normalizeCandidate(raw, base) {
  if (typeof raw !== "string") return null;

  let value = raw.trim()
    .replace(/&amp;/gi, "&")
    .replace(/\\u002[fF]/g, "/")
    .replace(/\\\//g, "/")
    .replace(/\\u0026/g, "&")
    .replace(/&quot;/g, '"');

  // Ignore non-HTTP resources and template placeholders.
  if (
    !value ||
    value.length > 8192 ||
    /^(?:data|blob|javascript|mailto):/i.test(value) ||
    /(?:\$\{|\{\{|<%|YOUR_|example\.com)/i.test(value)
  ) {
    return null;
  }

  try {
    const url = new URL(value, base);
    if (!["http:", "https:"].includes(url.protocol)) return null;
    url.hash = "";
    return url.href;
  } catch {
    return null;
  }
}

function discoverFromHtml(html, base) {
  const found = new Map();
  const $ = cheerio.load(html);

  function add(raw, source) {
    const url = normalizeCandidate(raw, base);
    if (!url) return;

    if (MEDIA_EXTENSIONS.test(url)) {
      found.set(url, { url, source });
    }
  }

  // DOM media elements and links.
  $("video, audio, source, track, iframe, embed, object, a, link").each(
    (_, element) => {
      const el = $(element);
      const tag = element.tagName.toLowerCase();

      for (const attr of ["src", "href", "data-src", "data-url", "data-file"]) {
        const value = el.attr(attr);
        if (value) add(value, `html:${tag}[${attr}]`);
      }

      const srcset = el.attr("srcset");
      if (srcset) {
        for (const item of srcset.split(",")) {
          add(item.trim().split(/\s+/)[0], `html:${tag}[srcset]`);
        }
      }
    }
  );

  // Open Graph, Twitter, and player metadata.
  $("meta").each((_, element) => {
    const el = $(element);
    const key = (
      el.attr("property") ||
      el.attr("name") ||
      el.attr("itemprop") ||
      ""
    ).toLowerCase();

    const value = el.attr("content");
    if (value && /video|stream|media|contenturl|manifest|audio/.test(key)) {
      add(value, `meta:${key}`);
    }
  });

  // JSON-LD and structured metadata.
  $('script[type="application/ld+json"]').each((_, element) => {
    const raw = $(element).contents().text();

    try {
      const walk = (node) => {
        if (!node || typeof node !== "object") return;

        for (const [key, value] of Object.entries(node)) {
          if (
            typeof value === "string" &&
            /^(?:contentUrl|embedUrl|url|streamingUrl)$/i.test(key)
          ) {
            add(value, `json-ld:${key}`);
          } else if (value && typeof value === "object") {
            walk(value);
          }
        }
      };

      walk(JSON.parse(raw));
    } catch {
      // Malformed JSON-LD is ignored.
    }
  });

  // Common player config keys in inline scripts.
  const scriptText = $("script").map((_, el) => $(el).html() || "").get().join("\n");
  const patterns = [
    /["'](?:file|src|source|url|hls|dash|manifest|contentUrl|videoUrl|streamUrl)["']\s*:\s*["']([^"'<>]{1,8192})["']/gi,
    /(?:https?:)?\/\/[^"'\\\s<>]+?\.(?:m3u8|mp4|m4v|mkv|webm|mov|avi|mpd|mp3|m4a|ts)(?:\?[^"'\\\s<>]*)?/gi
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(scriptText)) !== null) {
      add(match[1] || match[0], "inline-script");
      if (found.size >= MAX_RESULTS) break;
    }
  }

  return [...found.values()].slice(0, MAX_RESULTS);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function renderResults(originalUrl, results) {
  const rows = results.length
    ? results.map((item) => `
      <li>
        <a href="${escapeHtml(item.url)}" target="_blank"
           rel="noopener noreferrer">${escapeHtml(item.url)}</a>
        <small>${escapeHtml(item.source)}</small>
      </li>`).join("")
    : "<li>No recognizable media URLs were found.</li>";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Media Discovery Results</title>
<style>
  body{font:16px system-ui,sans-serif;max-width:960px;margin:48px auto;padding:0 20px;background:#0b1020;color:#eef2ff}
  h1{font-size:28px}p{color:#b6c2dd;overflow-wrap:anywhere}
  ul{padding:0;list-style:none}li{margin:12px 0;padding:16px;background:#141c31;border:1px solid #283552;border-radius:12px;overflow-wrap:anywhere}
  a{color:#8dbbff}small{display:block;color:#aab7d1;margin-top:8px}
  code{overflow-wrap:anywhere}
</style>
</head>
<body>
<h1>Media Discovery</h1>
<p>Source: <code>${escapeHtml(originalUrl)}</code></p>
<p>Found ${results.length} media URL(s).</p>
<ul>${rows}</ul>
</body>
</html>`;
}

app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Media Discovery API</title>
<body style="font:16px system-ui;max-width:720px;margin:50px auto;padding:20px">
<h1>Media Discovery API</h1>
<p>Find publicly accessible media URLs on pages you are authorized to inspect.</p>
<p>Usage: <code>/api?link=https%3A%2F%2Fexample.org%2Fvideo-page</code></p>
</body></html>`);
});

app.get("/health", (_req, res) => res.json({ ok: true }));

app.get("/api", async (req, res) => {
  const input = req.query.link;

  if (typeof input !== "string" || !input.trim() || input.length > 8192) {
    return res.status(400).send("Provide one valid link query parameter.");
  }

  try {
    const target = await validateUrl(input.trim());
    const cacheKey = target.href;
    const cached = cache.get(cacheKey);

    if (cached && cached.expires > Date.now()) {
      if (req.accepts("json") && !req.accepts("html")) {
        return res.json({ source: cacheKey, results: cached.results });
      }

      return res.type("html").send(renderResults(cacheKey, cached.results));
    }

    const { response, url: finalUrl } = await safeFetch(target.href);

    if (!response.ok) {
      await response.body?.cancel();
      return res.status(502).send(`Target returned HTTP ${response.status}.`);
    }

    const contentType = (response.headers.get("content-type") || "").toLowerCase();
    let results = [];

    if (
      MEDIA_EXTENSIONS.test(finalUrl.href) ||
      contentType.startsWith("video/") ||
      contentType.startsWith("audio/") ||
      PLAYLIST_TYPES.some((type) => contentType.includes(type)) ||
      contentType.includes("application/dash+xml")
    ) {
      await response.body?.cancel();
      results = [{ url: finalUrl.href, source: "direct-media-response" }];
    } else if (
      contentType.includes("text/html") ||
      contentType.includes("application/xhtml+xml") ||
      contentType.includes("javascript") ||
      contentType.includes("json") ||
      contentType.startsWith("text/plain")
    ) {
      const body = await readLimited(response);
      results = discoverFromHtml(body, finalUrl.href);
    } else {
      await response.body?.cancel();
    }

    cache.set(cacheKey, {
      expires: Date.now() + CACHE_TTL_MS,
      results
    });

    if (req.accepts("json") && !req.accepts("html")) {
      return res.json({ source: finalUrl.href, results });
    }

    return res.type("html").send(renderResults(finalUrl.href, results));
  } catch (error) {
    const message = error.message || "Discovery failed.";
    const status = /private|reserved|not allowed|valid URL|protocol|hostname/.test(message)
      ? 400
      : 502;

    return res.status(status).type("text").send(message);
  }
});

// Keep in-memory maps bounded.
setInterval(() => {
  const now = Date.now();

  for (const [key, value] of cache) {
    if (value.expires <= now) cache.delete(key);
  }

  if (requests.size > 10000) requests.clear();
}, 60_000).unref();

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Media Discovery API listening on port ${PORT}`);
});
