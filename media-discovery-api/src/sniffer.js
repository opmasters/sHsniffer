"use strict";

/**
 * The sniffing engine: BFS crawl of a page + its player iframes, resolving
 * HLS/DASH master playlists into renditions, auto-solving Cloudflare
 * Turnstile gates, all under one global time budget with request dedupe.
 */

const config = require("./config");
const { safeFetch, readLimited, HttpError, CookieJar } = require("./http-client");
const { extractFromDocument, MEDIA_EXT_RE, PLAYLIST_TYPES, classifyMediaType } = require("./extractors");
const turnstile = require("./turnstile");

class SniffError extends Error {
  constructor(message, statusCode = 502) {
    super(message);
    this.name = "SniffError";
    this.statusCode = statusCode;
  }
}

// ---------------------------------------------------------------------------
// Small promise-pool for bounded-concurrency fetch batches.
// ---------------------------------------------------------------------------
async function pool(items, worker, limit = config.concurrency) {
  const results = [];
  let index = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length) {
      const i = index++;
      try {
        results[i] = await worker(items[i], i);
      } catch {
        results[i] = undefined; // per-item failures never abort the batch
      }
    }
  });
  await Promise.all(runners);
  return results.filter(Boolean);
}

// ---------------------------------------------------------------------------
// Playlist parsing — resolve masters to variant/rendition URLs so callers get
// every playable stream (each quality level), not just the master.
// ---------------------------------------------------------------------------
function parseM3u8(text, baseUrl) {
  const out = [];
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;
    try {
      const resolved = new URL(line, baseUrl).href;
      const meta = { url: resolved, type: classifyMediaType(resolved) };

      // Back-annotate the preceding #EXT-X-STREAM-INF for bandwidth/resolution.
      for (let j = i - 1; j >= 0 && j > i - 4; j--) {
        const prev = lines[j];
        if (prev.includes("#EXTINF")) break;
        const inf = /#EXT-X-STREAM-INF:([^\r\n]+)/.exec(prev);
        if (inf) {
          const attrs = inf[1];
          const res = /RESOLUTION=(\d+x\d+)/i.exec(attrs);
          const bw = /BANDWIDTH=(\d+)/i.exec(attrs);
          const codeps = /CODECS="([^"]+)"/i.exec(attrs);
          if (res) meta.resolution = res[1];
          if (bw) meta.bandwidth = Number(bw[1]);
          if (codeps) meta.codecs = codeps[1];
          meta.type = "hls-rendition";
          break;
        }
      }
      out.push(meta);
    } catch { /* skip malformed entries */ }
  }
  return out;
}

function parseDash(text, baseUrl) {
  const out = [];
  // Representation ids & BaseURLs via regex (avoids a heavy XML parser).
  for (const m of text.matchAll(/<BaseURL\s*>\s*([^<]+?)\s*<\/BaseURL>/gi)) {
    try {
      const resolved = new URL(m[1].trim(), baseUrl).href;
      out.push({ url: resolved, type: classifyMediaType(resolved) || "dash-rendition" });
    } catch { /* ignore */ }
  }
  for (const m of text.matchAll(/(?:sourceURL|initialization|media)\s*=\s*["']([^"']+\.(?:mp4|m4s|webm|ts))["']/gi)) {
    try {
      out.push({ url: new URL(m[1], baseUrl).href, type: "dash-rendition" });
    } catch { /* ignore */ }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Main sniffer
// ---------------------------------------------------------------------------
async function sniff(targetUrl, options = {}) {
  const startedAt = Date.now();
  const deadlineAt = startedAt + (options.budgetMs ?? config.totalBudgetMs);
  const jar = new CookieJar(); // shared across the whole crawl (per-host isolated)
  const visited = new Set();

  const media = new Map();   // url -> {url,type,source,...}
  const notes = [];
  let turnstileSolved = false;

  const addMedia = (item) => {
    if (!item?.url) return;
    if (media.size >= config.maxResults) return;
    if (!media.has(item.url)) media.set(item.url, item);
  };

  async function fetchDoc(url, depth) {
    if (Date.now() > deadlineAt) throw new SniffError("Time budget exhausted.", 504);
    const { response, url: finalUrl } = await safeFetch(url, { jar, deadlineAt });

    const contentType = (response.headers.get("content-type") || "").toLowerCase();
    const isHtmlish =
      contentType.includes("text/html") ||
      contentType.includes("application/xhtml") ||
      contentType.includes("javascript") ||
      contentType.includes("json") ||
      contentType.startsWith("text/") ||
      contentType === "";

    // Direct media or playlist response?
    if (
      MEDIA_EXT_RE.test(finalUrl.href) ||
      contentType.startsWith("video/") ||
      contentType.startsWith("audio/") ||
      PLAYLIST_TYPES.some((t) => contentType.includes(t))
    ) {
      const direct = { url: finalUrl.href, type: classifyMediaType(finalUrl.href), source: `direct-response${depth ? `@depth${depth}` : ""}`, httpStatus: response.status };
      await response.body?.cancel().catch(() => {});
      return { kind: "media", item: direct };
    }

    if (!response.ok && !isHtmlish) {
      await response.body?.cancel().catch(() => {});
      throw new HttpError(`Target returned HTTP ${response.status}.`, 502);
    }

    let html = await readLimited(response);

    // --- Cloudflare Turnstile gate? ---------------------------------------
    if (turnstile.looksLikeChallenge(html, response)) {
      if (!config.turnstile.enabled || !config.turnstile.apiKey) {
        notes.push(
          "Cloudflare challenge detected but no solver key configured " +
            "(set PEAK_API_KEY on Render)."
        );
        throw new SniffError(
          "The target is protected by a Cloudflare Turnstile challenge. " +
            "Configure PEAK_API_KEY to enable automatic solving.",
          451
        );
      }
      notes.push("Cloudflare Turnstile detected — solving via Peak API…");
      const replayed = await turnstile.solveAndReplay(finalUrl.href, html, jar, deadlineAt);
      html = replayed.html;
      turnstileSolved = true;
      notes.push(`Turnstile bypassed (sitekey ${replayed.sitekey.slice(0, 8)}…).`);
      return { kind: "html", url: replayed.url.href, html };
    }

    return { kind: "html", url: finalUrl.href, html };
  }

  async function handlePlaylist(url, source, depth) {
    // Resolve master playlists one level deep so callers get concrete renditions.
    let resolved = false;
    try {
      const { response, url: finalUrl } = await safeFetch(url, { jar, deadlineAt });
      if (response.ok) {
        const text = await readLimited(response, 1024 * 1024); // playlists are small
        const isDash = /\.mpd(\?|$)/i.test(finalUrl.pathname) ||
          (response.headers.get("content-type") || "").includes("dash");
        const renditions = isDash
          ? parseDash(text, finalUrl.href)
          : parseM3u8(text, finalUrl.href);

        for (const r of renditions) {
          addMedia({ ...r, source: `${source}>playlist`, viaMaster: url, depth });
        }
        resolved = true;
        if (renditions.length) {
          addMedia({ url, type: /mpd/i.test(url) ? "dash-master" : "hls-master", source, renditionCount: renditions.length });
        } else {
          addMedia({ url, type: classifyMediaType(url), source }); // media playlist (segments inline)
        }
      } else {
        await response.body?.cancel().catch(() => {});
      }
    } catch { /* fall through — still return the playlist itself */ }

    if (!resolved) {
      addMedia({ url, type: classifyMediaType(url), source });
    }
  }

  // --- BFS over documents ---------------------------------------------------
  const queue = [{ url: targetUrl, depth: 0 }];
  visited.add(targetUrl);
  const playlistJobs = [];

  while (queue.length) {
    const batch = queue.splice(0, config.concurrency);
    await pool(batch, async ({ url, depth }) => {
      let doc;
      try {
        doc = await fetchDoc(url, depth);
      } catch (error) {
        notes.push(`fetch ${url}: ${error.message}`);
        return;
      }

      if (doc.kind === "media") {
        const item = doc.item;
        addMedia(item);
        if (/\.m3u8?($|[?#])/i.test(item.url) || /\.mpd($|[?#])/i.test(item.url)) {
          playlistJobs.push(item);
        }
        return;
      }

      const { media: found, frames } = extractFromDocument(doc.html, doc.url);
      for (const item of found.values()) {
        addMedia({ ...item, depth });
        if (/\.m3u8?($|[?#])/i.test(item.url) || /\.mpd($|[?#])/i.test(item.url)) {
          playlistJobs.push(item);
        }
      }

      // Queue iframes/players for deeper inspection (bounded by maxDepth).
      if (depth < config.maxDepth) {
        for (const frameUrl of frames) {
          if (!visited.has(frameUrl) && visited.size < 40) {
            visited.add(frameUrl);
            queue.push({ url: frameUrl, depth: depth + 1 });
          }
        }
      }
    });
  }

  // --- Resolve discovered playlists in parallel -----------------------------
  const uniquePlaylists = [...new Map(playlistJobs.map((p) => [p.url, p])).values()].slice(0, 20);
  await pool(uniquePlaylists, async (p) => handlePlaylist(p.url, p.source, p.depth ?? 0));

  const results = [...media.values()]
    .sort((a, b) => rank(a) - rank(b))
    .slice(0, config.maxResults);

  return {
    results,
    notes,
    stats: {
      durationMs: Date.now() - startedAt,
      pagesVisited: visited.size,
      turnstileSolved,
    },
  };
}

// Prefer "real" playable sources first: direct files > renditions > masters > embeds.
function rank(item) {
  const t = item.type || "";
  if (t === "mp4" || t === "matroska" || t === "webm" || t === "other-video") return 0;
  if (t === "hls-rendition" || t === "dash-rendition") return 1;
  if (t === "mpeg-ts") return 2;
  if (t === "hls-master" || t === "dash-master" || t === "hls") return 3;
  if (t === "smooth-streaming") return 4;
  if (t === "audio") return 5;
  return 6;
}

module.exports = { sniff, parseM3u8, parseDash, rank };
