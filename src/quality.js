"use strict";

/**
 * Quality inference + sorting for discovered media.
 *
 * Inspired by m3u8-sniffer tooling (e.g. github.com/Leenshady/m3u8Sniffer2),
 * which surfaces every captured .m3u8 request to the user. We go one step
 * further: each result carries a `quality` descriptor and the JSON response
 * is sorted best-first so callers can simply take results[0].
 *
 * Quality signals, in order of reliability:
 *   1. #EXT-X-STREAM-INF attributes on HLS master playlists (RESOLUTION,
 *      BANDWIDTH, VIDEO/CODECS) — exact values.
 *   2. DASH <Representation width/height/bandwidth/frameRate attributes.
 *   3. Filename / path hints used by virtually every CDN: _720p, /1080/,
 *      "hd", "sd", "high", "low", "360", ... — heuristic.
 *   4. Content-Length headers on progressive files → rough bitrate estimate.
 */

const QUALITY_LABELS = [
  { min: 2160, label: "4K UHD" },
  { min: 1440, label: "1440p QHD" },
  { min: 1080, label: "1080p FHD" },
  { min: 720, label: "720p HD" },
  { min: 480, label: "480p SD" },
  { min: 360, label: "360p" },
  { min: 240, label: "240p" },
  { min: 144, label: "144p" },
];

/** Human-readable bucket for a height (or null when unknown). */
function qualityLabel(height) {
  if (!Number.isFinite(height) || height <= 0) return null;
  const bucket = QUALITY_LABELS.find((q) => height >= q.min);
  return bucket ? bucket.label : `${height}p`;
}

/** Parse "1920x1080" style strings into {width,height}. */
function parseResolution(value) {
  const m = /(\d{2,5})\s*[x×*]\s*(\d{2,5})/i.exec(String(value || ""));
  if (!m) return {};
  return { width: Number(m[1]), height: Number(m[2]) };
}

/**
 * Heuristic height guess from a URL/path/name string. Returns null when no
 * confident hint exists. Only matches patterns that are unambiguous enough
 * to be useful (a lone "1080" next to p/px/q or in a filename token).
 */
function inferHeightFromText(text) {
  const s = String(text || "").toLowerCase();

  // Explicit "720p", "1080P", "576px", "480q" tokens.
  let m = /(4320|2160|1440|1080|960|854|720|640|576|540|480|426|360|320|240|180|144)(?:p|px|_p|-p)/.exec(s);
  if (m) return Number(m[1]);

  // Common CDN naming: "/video_1080.mp4", "hd720", "sd360".
  m = /(?:^|[^\d])(4320|2160|1440|1080|720|540|480|360|240|144)(?:[._\-\/]|$)/.exec(
    s.replace(/(\d{3,4})x\d{3,4}/g, "") // strip resolutions handled elsewhere
  );
  const candidate = m ? Number(m[1]) : null;

  // Named tiers as a fallback signal.
  if (/(?:^|[^a-z])(uhd|4k)(?:[^a-z]|$)/.test(s)) return 2160;
  if (/(?:^|[^a-z])(fhd|fullhd|full_hd)(?:[^a-z]|$)/.test(s)) return 1080;
  if (/(?:^|[^a-z])(qhd|2k)(?:[^a-z]|$)/.test(s)) return 1440;
  if (candidate && [4320, 2160, 1440, 1080, 720, 540, 480, 360, 240, 144].includes(candidate)) {
    return candidate;
  }
  return null;
}

/**
 * Attach/merge a quality descriptor onto a media item.
 * `attrs` comes from playlist parsing: {resolution, bandwidth, codecs, frameRate}.
 */
function applyQuality(item, attrs = {}) {
  const q = item.quality || {};

  const res = parseResolution(attrs.resolution ?? attrs.RESOLUTION ?? "");
  if (res.width) q.width = res.width;
  if (res.height) q.height = res.height;

  const bw = Number(attrs.bandwidth ?? attrs.BANDWIDTH ?? 0);
  if (bw > 0) q.bandwidth = bw;

  if (attrs.codecs) q.codecs = attrs.codecs;
  const fr = parseFloat(attrs.frameRate ?? attrs["frame-rate"] ?? "");
  if (Number.isFinite(fr) && fr > 0) q.frameRate = fr;

  // Fall back to text heuristics on url/viaMaster/source name.
  if (!q.height) {
    const guess =
      inferHeightFromText(item.url) ??
      inferHeightFromText(item.viaMaster || "") ??
      inferHeightFromText(q.name || "");
    if (guess) q.height = guess;
  }

  // Bitrate estimate from content-length when we have duration-less files.
  if (!q.bandwidth && Number.isFinite(item.sizeBytes) && Number.isFinite(item.durationSec) && item.durationSec > 0) {
    q.bandwidth = Math.round((item.sizeBytes * 8) / item.durationSec);
  }

  q.label = qualityLabel(q.height) || (q.bandwidth ? `${Math.round(q.bandwidth / 1000)} kbps` : "unknown");
  q.sortKey = computeSortKey(q);
  item.quality = q;
  return item;
}

/** Numeric key for descending-quality sort (higher = better). */
function computeSortKey(q) {
  let key = 0;
  if (q.height) key += q.height * 1000;                 // resolution dominates
  else if (q.bandwidth) key += Math.min(q.bandwidth / 10, 900_000); // bandwidth-only streams
  if (q.bandwidth) key += Math.min(q.bandwidth / 100_000, 999);     // tie-break within tier
  if (q.frameRate && q.frameRate > 30) key += 50;                    // prefer high-frame-rate
  return Math.round(key);
}

/**
 * Full comparator used before returning JSON:
 *   1. type rank (playable direct files & renditions first — see sniffer.rank)
 *   2. quality sortKey (best first)
 *   3. stable url ordering for determinism
 */
function compareResults(a, b, typeRank) {
  const ra = typeRank(a), rb = typeRank(b);
  if (ra !== rb) return ra - rb;
  const qa = a.quality?.sortKey ?? -1;
  const qb = b.quality?.sortKey ?? -1;
  if (qa !== qb) return qb - qa; // higher quality first
  return String(a.url).localeCompare(String(b.url));
}

module.exports = {
  QUALITY_LABELS,
  qualityLabel,
  parseResolution,
  inferHeightFromText,
  applyQuality,
  computeSortKey,
  compareResults,
};
