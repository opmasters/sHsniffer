"use strict";

/**
 * Network-request sniffing — the server-side analogue of what browser
 * m3u8 sniffer extensions (e.g. github.com/Leenshady/m3u8Sniffer2) do with
 * chrome.webRequest: watch every request a page makes and pluck out the
 * media URLs, including ones that are only fired lazily by the player after
 * load (hls.js/dash.js XHRs, token-refreshed manifests, segment requests).
 *
 * Since we have no real browser here, we approximate the "request stream"
 * two ways:
 *   1. RequestProbe: headless fetch replay loop. After parsing a document we
 *      keep polling candidate endpoints (API-ish urls found in the page, plus
 *      discovered playlists) inside the wait window; new media URLs appearing
 *      in responses/JSON payloads are emitted as they arrive. This catches
 *      manifests that a real browser would only request once playback starts.
 *   2. Referer/hydrated embed crawling is handled by the sniffer itself; this
 *      module supplies the *timing* primitive: waitForMedia() — poll until
 *      either `harvest()` reports new stable results, the settle window passes
 *      with no additions, or the max wait (default 20s) elapses.
 */

const config = require("./config");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Generic "wait for the pot to boil" helper implementing the up-to-20s grab:
 *
 *   await probe.waitFor(() => harvestCount() > 0)
 *
 * Semantics:
 *   - polls `predicate` every pollIntervalMs,
 *   - returns as soon as predicate is true AND the result set has been
 *     "settled" (no growth) for settleAfterMs — mirrors how extension users
 *     see links pop in one-by-one then stop,
 *   - hard-stops at min(waitMs, remaining budget) so we never blow past the
 *     overall deadline ("allow wait time of up to 20s to grab the url").
 *
 * Returns { satisfied, waitedMs, timedOut }.
 */
async function waitForMedia(predicate, options = {}) {
  const {
    waitMs = config.waitMs,
    pollIntervalMs = config.pollIntervalMs,
    settleAfterMs = config.settleAfterMs,
    deadlineAt = Infinity,
  } = options;

  const startedAt = Date.now();
  const maxUntil = Math.min(startedAt + waitMs, deadlineAt);
  let lastCount = -1;
  let lastChangeAt = Date.now();
  let satisfied = false;

  while (Date.now() < maxUntil) {
    let count = 0;
    try {
      count = Number(await predicate()) || 0;
    } catch {
      count = 0;
    }

    if (count !== lastCount) {
      lastCount = count;
      lastChangeAt = Date.now();
      satisfied = count > 0;
    } else if (satisfied && Date.now() - lastChangeAt >= settleAfterMs) {
      break; // everything that's coming has come
    }

    if (!Number.isFinite(maxUntil) && satisfied) break;
    await sleep(Math.min(pollIntervalMs, Math.max(50, maxUntil - Date.now())));
  }

  return { satisfied: lastCount > 0, waitedMs: Date.now() - startedAt };
}

/**
 * A tiny rolling dedupe buffer, like the extension's per-tab link list:
 * keeps insertion order, ignores exact duplicates and query-stripped
 * duplicates for badge-style counting.
 */
class SniffLedger {
  constructor() {
    this.items = [];          // ordered unique entries
    this.seen = new Set();    // exact urls
    this.stripQuery = new Map(); // url without query -> first full url
  }

  add(url, meta = {}) {
    if (!url || this.seen.has(url)) return false;
    this.seen.add(url);
    const base = url.includes("?") ? url.slice(0, url.indexOf("?")) : url;
    if (!this.stripQuery.has(base)) this.stripQuery.set(base, url);
    this.items.push({ url, ...meta });
    return true;
  }

  get size() {
    return this.items.length;
  }

  /** Count distinct base paths matching an m3u8-ish pattern (badge number). */
  countMatching(re) {
    let n = 0;
    for (const key of this.stripQuery.keys()) if (re.test(key)) n++;
    return n;
  }
}

module.exports = { waitForMedia, sleep, SniffLedger };
