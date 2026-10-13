"use strict";

/**
 * The sniffing engine: BFS crawl of a page + its player iframes, resolving
 * HLS/DASH master playlists into renditions, auto-solving Cloudflare
 * Turnstile gates, all under one global time budget with request dedupe.
 *
 * m3u8Sniffer2-inspired additions (github.com/Leenshady/m3u8Sniffer2):
 *   - passive "wait window": keep polling discovered endpoints for up to
 *     WAIT_MS (default 20s) so lazily-fired manifests show up before we give
 *     an answer — like watching webRequest traffic in the extension,
 *   - per-stream `headers` (Referer/Origin/User-Agent) recorded so consumers
 *   can replay requests that are hotlink-protected,
 *   - query-stripped dedupe ledger so token-refresh duplicates of the same
 *     manifest collapse into one entry,
 *   - results returned as JSON sorted by quality (best rendition first).
 */

const config = require("./config");
const { safeFetch, readLimited, HttpError, CookieJar } = require("./http-client");
const { extractFromDocument, MEDIA_EXT_RE, PLAYLIST_TYPES, classifyMediaType } = require("./extractors");
const turnstile = require("./turnstile");
const quality = require("./quality");
const { waitForMedia, SniffLedger, sleep } = require("./net-probe");

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
          const fr = /FRAME-RATE=([\d.]+)/i.exec(attrs);
          const name = /NAME="([^"]+)"/i.exec(attrs);
          if (res) meta.resolution = res[1];
          if (bw) meta.bandwidth = Number(bw[1]);
          if (codeps) meta.codecs = codeps[1];
          if (fr) meta.frameRate = parseFloat(fr[1]);
          if (name) meta.streamName = name[1];
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
  // <Representation width= height= bandwidth= frameRate=> — real quality data.
  for (const m of text.matchAll(/<Representation\b([^>]*)>/gi)) {
    const attrs = m[1];
    const get = (name) => {
      const mm = new RegExp(`${name}\\s*=\\s*"([^"]+)"`, "i").exec(attrs);
      return mm ? mm[1] : undefined;
    };
    const item = { type: "dash-rendition" };
    const w = get("width");
    const h = get("height");
    if (w && h) item.resolution = `${w}x${h}`;
    else if (h) item.resolution = `x${h}`;
    if (get("bandwidth")) item.bandwidth = Number(get("bandwidth"));
    if (get("frameRate")) item.frameRate = parseFloat(String(get("frameRate")).replace("/", "."));
    if (get("codecs")) item.codecs = get("codecs");
    const baseUrlTag = /<BaseURL\s*>\s*([^<]+?)\s*<\/BaseURL>/i.exec(attrs);
    try {
      item.url = new URL(baseUrlTag ? baseUrlTag[1].trim() : baseUrl, baseUrl).href;
      out.push(item);
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
  const ledger = new SniffLedger(); // m3u8Sniffer2-style deduped request log
  let turnstileSolved = false;

  const addMedia = (item) => {
    if (!item?.url) return;
    if (media.size >= config.maxResults) return;
    if (!media.has(item.url)) {
      media.set(item.url, item);
      ledger.add(item.url, { type: item.type });
    } else if (item.quality && !media.get(item.url).quality) {
      // Later playlist metadata enriches an earlier bare sighting.
      media.set(item.url, { ...media.get(item.url), ...item });
    }
  };

  /**
   * Hotlink-protection helper (m3u8Sniffer2 users learn quickly that raw
   * manifest urls often 403 without the right headers): record the page URL
   * each stream was discovered from so we can emit ready-to-use request
   * headers per result.
   */
  const requiredHeadersFor = (pageUrl) => {
    try {
      const u = new URL(pageUrl);
      return {
        "User-Agent": config.userAgent,
        Referer: pageUrl,
        Origin: `${u.protocol}//${u.host}`,
      };
    } catch {
      return undefined;
    }
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

  /**
   * Passive-capture poll round (m3u8Sniffer2's webRequest watcher, server
   * side): re-fetch known playlists and player-API candidates inside the
   * wait window. Hosts that only emit their real manifest after a token
   * handshake or on second request get caught here. New urls flow into the
   * shared `media` map via addMedia(), which grows `ledger.size` — the
   * signal waitForMedia() watches.
   */
  async function pollRound(candidates) {
    if (Date.now() > deadlineAt) return;
    await pool(candidates, async (p) => {
      try {
        const { response, url: finalUrl } = await safeFetch(p.url, { jar, deadlineAt });
        if (!response.ok) {
          await response.body?.cancel().catch(() => {});
          return;
        }
        const contentType = (response.headers.get("content-type") || "").toLowerCase();
        const text = await readLimited(response, 512 * 1024);
        const looksJson = contentType.includes("json") || /^\s*[{[]/.test(text);

        if (/mpegurl|dash/i.test(contentType) || /\.(m3u8|mpd)(\?|$)/i.test(finalUrl.pathname)) {
          const renditions = /\.mpd/i.test(finalUrl.pathname)
            ? parseDash(text, finalUrl.href)
            : parseM3u8(text, finalUrl.href);
          for (const r of renditions) {
            addMedia({ ...r, source: `${p.source}>poll`, viaMaster: p.url, depth: p.depth ?? 0, discoveredViaPoll: true });
          }
        } else if (looksJson || contentType.includes("json")) {
          try {
            const found = extractFromDocument(text, finalUrl.href).media;
            for (const item of found.values()) {
              addMedia({ ...item, depth: p.depth ?? 0, discoveredViaPoll: true });
              if (/\.(m3u8|mpd)($|[?#])/i.test(item.url) && !pollTargets.has(item.url)) {
                pollTargets.set(item.url, { url: item.url, source: "poll-discovered", depth: p.depth ?? 0 });
              }
            }
          } catch { /* non-JSON body, ignore */ }
        } else {
          // HTML/JS response — run the full static extractor over it.
          const found = extractFromDocument(text, finalUrl.href).media;
          for (const item of found.values()) {
            addMedia({ ...item, depth: p.depth ?? 0, discoveredViaPoll: true });
          }
        }
      } catch { /* transient poll failures are fine; next round retries */ }
    }, Math.min(config.concurrency, 4));
  }

  // --- BFS over documents ---------------------------------------------------
  const queue = [{ url: targetUrl, depth: 0 }];
  visited.add(targetUrl);
  const playlistJobs = [];
  // Rolling set of endpoints polled during the passive-capture wait window.
  const pollTargets = new Map();

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

  // --- Passive-capture wait window (up to WAIT_MS / 20s by default) ---------
  // Like the extension watching webRequest traffic: keep polling until either
  // new streams stop arriving (settle) or the wait budget runs out. Skipped
  // when `wait: false` is passed (e.g. warm cache refreshes) and shortened
  // automatically if we already have results and the caller opted into a
  // quick answer (`options.waitMs`).
  for (const p of uniquePlaylists) {
    pollTargets.set(p.url, { url: p.url, source: p.source || "page", depth: p.depth ?? 0 });
  }

  const waitEnabled = options.wait !== false && config.waitMs > 0;
  let waitedMs = 0;
  // Poll when we have endpoints to re-check, or when nothing was found yet
  // (give lazily-generated streams the full grace period either way).
  if (waitEnabled && (pollTargets.size > 0 || ledger.size === 0)) {
    const baseline = ledger.size;
    const wait = await waitForMedia(
      async () => {
        await pollRound([...pollTargets.values()].slice(0, 12));
        return ledger.size;
      },
      {
        waitMs: Math.min(options.waitMs ?? config.waitMs, Math.max(0, deadlineAt - Date.now())),
        deadlineAt,
      }
    );
    waitedMs = wait.waitedMs;
    if (ledger.size > baseline) {
      notes.push(`Wait window captured ${ledger.size - baseline} additional stream(s).`);
      // One final resolve pass so newly surfaced masters get renditions too.
      const fresh = [...media.values()].filter(
        (m) => /\.(m3u8|mpd)($|[?#])/i.test(m.url) && !m.renditionCount && !pollTargets.has(m.url)
      );
      if (fresh.length) {
        for (const f of fresh) pollTargets.set(f.url, { url: f.url, source: f.source, depth: f.depth ?? 0 });
        await pool(fresh.slice(0, 10), async (p) => handlePlaylist(p.url, p.source, p.depth ?? 0));
      }
    }
  }

  // --- Quality annotation + JSON sorted by quality ---------------------------
  const pageHeaders = requiredHeadersFor(targetUrl);
  const results = [...media.values()]
    .map((item) => {
      quality.applyQuality(item, {
        resolution: item.resolution,
        bandwidth: item.bandwidth,
        codecs: item.codecs,
        frameRate: item.frameRate,
      });
      if (item.streamName && item.quality) item.quality.name = item.streamName;
      if (pageHeaders) item.headers = pageHeaders; // replay headers for hotlink-protected streams
      return item;
    })
    .sort((a, b) => quality.compareResults(a, b, rank))
    .slice(0, config.maxResults);

  return {
    results,
    notes,
    stats: {
      durationMs: Date.now() - startedAt,
      waitMs: waitedMs,
      pagesVisited: visited.size,
      uniqueRequestsLogged: ledger.size,
      m3u8Captured: ledger.countMatching(/\.m3u8?$/i),
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

