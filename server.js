"use strict";

/**
 * vid-sniffer — industrial-grade video URL sniffer for Render.
 *
 *   GET /api?url=https://site.com/watch/abc123        -> JSON (all media found)
 *   GET /api?link=...                                 -> alias (back-compat)
 *   GET /embed?url=...                                -> HTML player page
 *   GET /health                                       -> Render health check
 *
 * Design notes for Render:
 *   - binds process.env.PORT (Render injects it; default 10000)
 *   - graceful SIGTERM/SIGINT shutdown so redeploys are seamless
 *   - no native deps, single Node process, in-memory LRU + request dedupe
 *   - keep-alive friendly; free tier sleeps on idle and wakes on request
 */

const express = require("express");
const config = require("./src/config");
const { validateUrl } = require("./src/safety");
const { sniff } = require("./src/sniffer");
const { looksLikeChallenge } = require("./src/turnstile");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", true); // Render terminates TLS at its proxy

// ---------------------------------------------------------------------------
// Middleware: security headers + per-IP token-bucket-ish rate limit
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Referrer-Policy", "no-referrer");
  res.set("X-Frame-Options", "DENY");
  next();
});

const rateBuckets = new Map();
setInterval(() => {
  const cutoff = Date.now() - 120_000;
  for (const [ip, bucket] of rateBuckets) {
    if (bucket.resetAt < cutoff) rateBuckets.delete(ip);
  }
}, 60_000).unref();

app.use((req, res, next) => {
  const now = Date.now();
  const ip = req.ip || "unknown";
  let bucket = rateBuckets.get(ip);
  if (!bucket || now > bucket.resetAt) {
    bucket = { count: 0, resetAt: now + 60_000 };
    rateBuckets.set(ip, bucket);
  }
  if (++bucket.count > config.rateLimitPerMinute) {
    res.set("Retry-After", String(Math.ceil((bucket.resetAt - now) / 1000)));
    return res.status(429).json({ error: "Rate limit exceeded. Try again shortly." });
  }
  next();
});

// ---------------------------------------------------------------------------
// TTL cache + in-flight request coalescing (identical concurrent sniffs run
// once; everyone else awaits the same promise). Keeps Render free tier fast.
// ---------------------------------------------------------------------------
const cache = new Map(); // key -> { expires, value, negative }

function cacheGet(key) {
  const hit = cache.get(key);
  if (!hit) return null;
  if (hit.expires <= Date.now()) {
    cache.delete(key);
    return null;
  }
  // refresh recency (cheap LRU via Map ordering)
  cache.delete(key);
  cache.set(key, hit);
  return hit.value;
}

function cacheSet(key, value, negative = false) {
  if (cache.size >= config.cacheMaxEntries) {
    const oldest = cache.keys().next().value;
    cache.delete(oldest);
  }
  cache.set(key, {
    expires: Date.now() + (negative ? config.negativeCacheTtlMs : config.cacheTtlMs),
    value,
    negative,
  });
}

const inflight = new Map(); // key -> Promise

function coalescedSniff(cacheKey, targetUrl) {
  const existing = inflight.get(cacheKey);
  if (existing) return existing;

  const job = sniff(targetUrl.href).finally(() => inflight.delete(cacheKey));
  inflight.set(cacheKey, job);
  return job;
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    uptimeSec: Math.round(process.uptime()),
    turnstileSolver: config.turnstile.apiKey ? "ready" : "not-configured",
    memoryMB: Math.round(process.memoryUsage().rss / 1e6),
  });
});

function readTargetParam(req) {
  const raw = req.query.url ?? req.query.link ?? req.query.u ?? req.query.q;
  if (typeof raw !== "string" || !raw.trim() || raw.length > 8192) return null;
  return raw.trim();
}

async function runSniff(req, res) {
  const input = readTargetParam(req);
  if (!input) {
    return res.status(400).json({
      error: "Provide the page to inspect as ?url=<page>",
      example: "/api?url=https://videohere.com/view",
    });
  }

  let target;
  try {
    target = await validateUrl(input);
  } catch (error) {
    return res.status(error.statusCode || 400).json({ error: error.message });
  }

  const cacheKey = target.href;
  const cached = cacheGet(cacheKey);
  if (cached) {
    res.set("X-Cache", "HIT");
    return res.json(cached);
  }
  res.set("X-Cache", "MISS");

  try {
    const outcome = await coalescedSniff(cacheKey, target);
    const payload = {
      source: target.href,
      count: outcome.results.length,
      primary: outcome.results[0] || null,
      results: outcome.results,
      stats: outcome.stats,
      notes: outcome.notes,
      generatedAt: new Date().toISOString(),
    };
    cacheSet(cacheKey, payload, outcome.results.length === 0);
    return res.json(payload);
  } catch (error) {
    const status = error.statusCode || 502;
    if (status >= 500) cacheSet(cacheKey, { error: error.message }, true);
    return res.status(status).json({ error: error.message || "Sniff failed." });
  }
}

// JSON API — the main entry point.
app.get("/api", runSniff);
app.get("/sniff", runSniff);
app.get("/v1/sniff", runSniff);

// Convenience: an embeddable HTML5 player page for the first/best source.
app.get("/embed", async (req, res) => {
  const input = readTargetParam(req);
  if (!input) return res.status(400).send("Provide ?url=<page>");

  try {
    const target = await validateUrl(input);
    const cached = cacheGet(target.href);
    const outcome = cached ? { results: cached.results } : await coalescedSniff(target.href, target);
    const best = outcome.results?.[0];
    if (!best) return res.status(404).send("No media found on that page.");

    const isHls = /m3u8|mpd|ism|isml|m3u($|[?#])/i.test(best.url);
    res.type("html").send(`<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Vid Sniffer Player</title>
<script src="https://cdn.jsdelivr.net/npm/hls.js@1/dist/hls.min.js"></script></head>
<body style="margin:0;background:#000">
<video id="v" controls autoplay playsinline style="width:100vw;height:100vh"></video>
<script>
var src=${JSON.stringify(best.url)},v=document.getElementById('v');
if(${isHls}&&window.Hls&&Hls.isSupported()){var h=new Hls();h.loadSource(src);h.attachMedia(v);}
else{v.src=src;}
</script></body></html>`);
  } catch (error) {
    res.status(error.statusCode || 502).send(error.message);
  }
});

// Landing page / docs.
app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>vid-sniffer</title></head>
<body style="font:16px system-ui;max-width:760px;margin:48px auto;padding:0 20px;background:#0b1020;color:#eef2ff">
<h1>🎬 vid-sniffer</h1>
<p>Industrial-grade video URL discovery. Point it at any page and it returns every embedded
stream it can find — HLS (<code>.m3u8</code>), DASH (<code>.mpd</code>), MPEG-TS, MP4, MKV, WebM, MOV,
FLV, AVI and audio — including all quality renditions resolved from master playlists.</p>
<h2>API</h2>
<pre style="background:#141c31;padding:16px;border-radius:10px;overflow:auto"><code>GET /api?url=https%3A%2F%2Fvideohere.com%2Fview
GET /embed?url=https%3A%2F%2Fvideohere.com%2Fview   (HTML5 player)
GET /health</code></pre>
<p>Cloudflare Turnstile-protected pages are solved automatically when a solver key
(<code>PEAK_API_KEY</code>) is configured — powered by the
<a style="color:#8dbbff" href="https://github.com/henryzawadzki6542/cloudflare-turnstile-bypass">cloudflare-turnstile-bypass</a>
protocol.</p>
</body></html>`);
});

app.use((_req, res) => res.status(404).json({ error: "Not found. See / for usage." }));

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Internal error." });
});

// ---------------------------------------------------------------------------
// Boot + graceful shutdown (Render sends SIGTERM on redeploy/spin-down)
// ---------------------------------------------------------------------------
const server = app.listen(config.port, "0.0.0.0", () => {
  console.log(`vid-sniffer listening on :${config.port} (turnstile: ${config.turnstile.apiKey ? "solver ready" : "no key"})`);
});

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    console.log(`${signal} received — draining connections…`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 8_000).unref(); // hard stop for Render
  });
}

module.exports = app;
