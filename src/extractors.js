"use strict";

/**
 * Static media extraction: given an HTML/JS/JSON document and its base URL,
 * return every plausible media URL plus any iframe/player URLs worth a deeper
 * crawl. Pure functions — no I/O — so they are fast and unit-testable.
 */

const cheerio = require("cheerio");
const config = require("./config");

// All video/audio container + streaming formats the sniffer recognises.
const VIDEO_EXT = "m3u8|m3u|mpd|ts|m2ts|mp4|m4v|mkv|webm|mov|avi|mpg|mpeg|ogv|ogg|wmv|flv|f4v|3gp|vob|m4s|ism|isml";
const AUDIO_EXT = "mp3|m4a|aac|wav|flac|opus|oga";
const MEDIA_EXT_RE = new RegExp(
  String.raw`\.(?:${VIDEO_EXT}|${AUDIO_EXT})(?:$|[?#])`,
  "i"
);

const PLAYLIST_TYPES = [
  "application/vnd.apple.mpegurl",
  "application/x-mpegurl",
  "audio/mpegurl",
  "application/dash+xml",
  "video/mp2t",
];

const KNOWN_HOST_PATTERNS = [
  // jwplayer setups: file/sources/setup configs
  { re: /(?:jwplayer|jwp)\s*\(\s*["']?[^)"]*["']?\s*\)\s*\.setup\s*\(\s*(\{[\s\S]{0,20000}?\})\s*\)/gi, kind: "jwplayer-setup" },
  // Brightcove policy/keyed sources
  { re: /brightcove[^"']*["'][^"']*["']/gi, kind: "brightcove" },
  // common video.js / plyr / flowplayer data attributes handled via DOM pass
];

// Inline-script key names whose values are usually media URLs.
const CONFIG_KEY_RE =
  /["'](?:file|sources?|src|url|hls|dash|manifest|contentUrl|embedUrl|videoUrl|streamUrl|stream_url|video_src|mp4|mp4_h264|mp4_h265|web_h264|playbackUrl|playlist|packaged_js_url)["']\s*:\s*["']([^"'<>\\]{1,8192})["']/gi;

// Bare absolute/partial media URLs anywhere in text (scheme-relative allowed).
const BARE_MEDIA_RE =
  /(?:https?:)?\/\/[^\s"'`<>\\]*\.(?:m3u8|m3u|mpd|ts|mp4|m4v|mkv|webm|mov|avi|flv|mpg|mpeg|ogv|wmv|m4a|mp3|m4s|f4v|3gp|vob|m2ts|aac|wav|flac|opus)(?:[?#][^\s"'`<>\\]*)?/gi;

// Protocol-relative or bare-domain media URLs that may omit "//" after escaping.
const REL_MEDIA_RE =
  /\b[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?\/[^\s"'`<>\\]*\.(?:m3u8|mpd|ts|mp4|mkv|webm|mov|avi|flv|m4a|mp3)(?:[?#][^\s"'`<>\\]*)?/gi;

function normalizeCandidate(raw, base) {
  if (typeof raw !== "string") return null;

  let value = raw
    .trim()
    .replace(/&amp;/gi, "&")
    .replace(/\\u002[fF]/g, "/")
    .replace(/\\\//g, "/")
    .replace(/\\u0026/g, "&")
    .replace(/&quot;/g, '"');

  if (
    !value ||
    value.length > 8192 ||
    /^(?:data|blob|javascript|mailto|about):/i.test(value) ||
    /\$\{|\{\{|<%|__REPLACE__|TBD\.com/i.test(value) // template placeholders only
  ) {
    return null;
  }

  try {
    const url = new URL(value, base);
    if (!["http:", "https:"].includes(url.protocol)) return null;
    // Only reject template placeholders that survive inside path/query.
    if (/[<>"'`\\]|\$\{|<%/.test(url.href)) return null;
    url.hash = "";
    return url.href;
  } catch {
    return null;
  }
}

function classifyMediaType(url) {
  const path = url.toLowerCase();
  if (/\.m3u8/.test(path)) return "hls";
  if (/\.mpd/.test(path)) return "dash";
  if (/\.m3u($|[?#])/.test(path)) return "m3u-playlist";
  if (/\.(?:ism|isml)(?:$|[?#])/.test(path)) return "smooth-streaming";
  if (/\.ts(?:$|[?#])/.test(path) || /\/\d+\.ts\b/.test(path)) return "mpeg-ts";
  if (/\.mkv(?:$|[?#])/.test(path)) return "matroska";
  if (/\.webm(?:$|[?#])/.test(path)) return "webm";
  if (/\.(?:mp4|m4v|mov|m4a)(?:$|[?#])/.test(path)) return "mp4";
  if (/\.(?:mp3|aac|wav|flac|opus|ogg|oga)(?:$|[?#])/.test(path)) return "audio";
  if (/\.(?:avi|flv|wmv|mpg|mpeg|3gp|vob|ogv|m2ts)(?:$|[?#])/.test(path)) return "other-video";
  return "media";
}

/**
 * Extract everything from one document.
 * Returns { media: Map<url,{url,type,source,quality?}>, frames: Set<url> }
 */
function extractFromDocument(text, base) {
  const media = new Map();
  const frames = new Set();

  const addMedia = (raw, source, extra = {}) => {
    const url = normalizeCandidate(raw, base);
    if (!url) return;
    if (!media.has(url)) {
      media.set(url, { url, type: classifyMediaType(url), source, ...extra });
    }
  };

  const addFrame = (raw, source) => {
    const url = normalizeCandidate(raw, base);
    if (url && !frames.has(url)) frames.add(url);
    if (url && MEDIA_EXT_RE.test(url)) addMedia(url, source);
  };

  let html = text;

  // If it's JSON (API responses from video hosts), walk it generically.
  const trimmed = text.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const walk = (node, keyHint) => {
        if (typeof node === "string") {
          if (keyHint && /url|src|file|stream|manifest|playlist|path/i.test(keyHint)) {
            addMedia(node, `json:${keyHint}`);
          }
          // Bare media URLs inside arbitrary strings.
          for (const m of node.matchAll(BARE_MEDIA_RE)) addMedia(m[0], "json:string");
          return;
        }
        if (Array.isArray(node)) return node.forEach((n) => walk(n, keyHint));
        if (node && typeof node === "object") {
          for (const [k, v] of Object.entries(node)) walk(v, k);
        }
      };
      walk(JSON.parse(trimmed), null);
      return { media, frames };
    } catch {
      /* fall through to HTML parsing */
    }
  }

  const $ = cheerio.load(html);

  // --- DOM elements -------------------------------------------------------
  $("video, audio, source, track, iframe, embed, object, a, link").each((_, el) => {
    const $el = $(el);
    const tag = el.tagName.toLowerCase();

    for (const attr of ["src", "href", "data-src", "data-url", "data-file", "data-hls-url", "data-mp4-url", "data-video", "poster"]) {
      const value = $el.attr(attr);
      if (value) {
        if (tag === "iframe" && attr === "src") addFrame(value, `html:iframe`);
        else if (attr !== "poster") addMedia(value, `html:${tag}[${attr}]`);
      }
    }

    // srcset-style multi-source attributes used by players
    for (const attr of ["srcset", "data-srcset"]) {
      const srcset = $el.attr(attr);
      if (srcset) {
        for (const item of srcset.split(",")) {
          addMedia(item.trim().split(/\s+/)[0], `html:${tag}[${attr}]`);
        }
      }
    }

    // data-* blobs that contain JSON player configs (video.js style)
    for (const [name, value] of Object.entries($el.data?.() ?? {})) {
      if (typeof value === "string" && MEDIA_EXT_RE.test(value)) {
        addMedia(value, `dataset:${tag}.${name}`);
      }
    }
  });

  // Nested <source> quality hints inside <video>
  $("video source").each((_, el) => {
    const $el = $(el);
    const src = $el.attr("src");
    if (src) addMedia(src, "html:video>source", { quality: $el.attr("size") || $el.attr("label") || undefined });
  });

  // --- Meta tags (Open Graph / Twitter / oEmbed) --------------------------
  $("meta").each((_, el) => {
    const $el = $(el);
    const key = ($el.attr("property") || $el.attr("name") || $el.attr("itemprop") || "").toLowerCase();
    const value = $el.attr("content");
    if (value && /video|stream|media|manifest|player|embed/.test(key)) {
      if (/player|embed|iframe/.test(key)) addFrame(value, `meta:${key}`);
      else addMedia(value, `meta:${key}`);
    }
  });

  $('link[rel="preload"], link[rel="prefetch"]').each((_, el) => {
    const href = $(el).attr("href");
    const as = ($(el).attr("as") || "").toLowerCase();
    if (href && ["video", "audio"].includes(as)) addMedia(href, "link[preload]");
  });

  // --- JSON-LD -------------------------------------------------------------
  $('script[type="application/ld+json"]').each((_, el) => {
    const raw = $(el).contents().text();
    try {
      const walk = (node) => {
        if (!node || typeof node !== "object") return;
        for (const [key, value] of Object.entries(node)) {
          if (typeof value === "string" && /^(?:contentUrl|embedUrl|url|streamingUrl)$/i.test(key)) {
            addMedia(value, `json-ld:${key}`);
          } else if (value && typeof value === "object") {
            walk(value);
          }
        }
      };
      walk(JSON.parse(raw));
    } catch { /* malformed JSON-LD ignored */ }
  });

  // --- Inline scripts ------------------------------------------------------
  const scriptText = $("script")
    .map((_, el) => $(el).html() || "")
    .get()
    .join("\n") + "\n" + $.html(); // full doc too — catches urls outside <script>

  for (const match of scriptText.matchAll(CONFIG_KEY_RE)) {
    addMedia(match[1], "inline-script:key-value");
  }
  for (const match of scriptText.matchAll(BARE_MEDIA_RE)) {
    addMedia(match[0], "inline-script:bare-url");
  }
  for (const match of scriptText.matchAll(REL_MEDIA_RE)) {
    addMedia(`https://${match[0]}`, "inline-script:relative-host");
  }

  // --- Known player signatures --------------------------------------------
  // JW Player .setup({...}) blocks — grab every url-ish string inside.
  for (const [, blob] of scriptText.matchAll(/\.setup\s*\(\s*(\{[\s\S]{0,20000}?\})\s*(?:\)\s*;|\)\s*\))/gi)) {
    for (const m of blob.matchAll(/["']((?:https?:)?\/\/[^"']+|\/[^"']+\.(?:m3u8|mp4|webm|mkv|ts))["']/gi)) {
      addMedia(m[1], "jwplayer:setup");
    }
  }
  // Flowplayer / Plyr / Video.js data attrs already covered; Cloudflare Stream:
  for (const m of scriptText.matchAll(/(?:videos\.cloudflare\.stream|customer-.*\.videodelivery\.net)\/([a-zA-Z0-9]+)/g)) {
    addMedia(`https://videodelivery.net/${m[1]}/manifest/video.m3u8`, "cloudflare-stream");
    addMedia(`https://embed.videodelivery.net/embed/${m[1]}`, "cloudflare-stream-embed");
  }
  // Twitch/Vimeo/Loom/others embeds -> frames for deep crawl
  for (const m of scriptText.matchAll(/(?:player\.)?(vimeo\.com\/(?:video\/|external\/)?\d+|www\.loom\.com\/embed\/[a-zA-Z0-9]+|player\.twitch\.tv\/\?.*?channel=[a-zA-Z0-9_]+)/gi)) {
    addFrame(m[0].startsWith("http") ? m[0] : `https://${m[0]}`, "known-embed");
  }

  return { media, frames };
}

module.exports = {
  extractFromDocument,
  normalizeCandidate,
  classifyMediaType,
  MEDIA_EXT_RE,
  PLAYLIST_TYPES,
  VIDEO_EXT,
};
