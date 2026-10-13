"use strict";

/**
 * Cloudflare Turnstile solver — a faithful Node port of
 * https://github.com/henryzawadzki6542/cloudflare-turnstile-bypass
 * (Peak API protocol).
 *
 * Flow, mirroring the upstream package:
 *   1. find_sitekey(html)  – locate the `data-sitekey` on the challenge page
 *   2. find_action(html)   – optional `data-action` / `action` attribute
 *   3. bypass_turnstile()  – POST {task_type:"turnstiletask", sitekey, url, action}
 *                            to the Peak solve API with X-API-Key auth, retry w/
 *                            backoff, read data.token
 *   4. inject the returned cf-turnstile-response token into a form POST / GET
 *      exactly like a browser would after completing the widget, and keep the
 *      resulting cf_clearance cookie in the shared jar for follow-up requests.
 *
 * Also detects the interstitial "Just a moment..." / challenge markers so the
 * sniffer knows when it has been gated.
 */

const config = require("./config");
const { safeFetch, readLimited } = require("./http-client");

// Same regexes as the upstream Python package.
const SITEKEY_RE =
  /data-sitekey\s*=\s*["']([^"']+)["']|(?:sitekey|render)\s*[:=]\s*["']([^"']+)["']/i;
const ACTION_RE = /data-action\s*=\s*["']([^"']+)["']/i;

class TurnstileError extends Error {
  constructor(message, statusCode = 503) {
    super(message);
    this.name = "TurnstileError";
    this.statusCode = statusCode;
  }
}

/** Cheap markers that a page is a Cloudflare challenge rather than content. */
function looksLikeChallenge(html, response) {
  const status = response?.status;
  if (status === 403 || status === 503) return true;
  if (!html) return false;
  return (
    /challenge-platform|cf-chl|__cf_chl/i.test(html) ||
    /Just a moment/i.test(html) ||
    /Attention Required! \| Cloudflare/i.test(html) ||
    /cf-turnstile-response/i.test(html)
  );
}

function findSitekey(html) {
  for (const match of html.matchAll(new RegExp(SITEKEY_RE, "gi"))) {
    const candidate = match.slice(1).find(Boolean);
    if (candidate) return candidate.trim();
  }
  // Turnstile script tags sometimes carry ?sitekey=... query params.
  const q = /[?&]sitekey=([\w-]{8,})/i.exec(html);
  if (q) return q[1];
  return null;
}

function findAction(html) {
  const m = ACTION_RE.exec(html);
  return m ? m[1].trim() : null;
}

function buildPayload({ sitekey, url, proxy, action, cdata }) {
  const payload = { task_type: "turnstiletask", sitekey, url };
  if (proxy) payload.proxy = proxy;
  if (action) payload.action = action;
  if (cdata) payload.cdata = cdata;
  return payload;
}

/**
 * Solve a Turnstile challenge for `sitekey` on `url` via the Peak API.
 * Returns BypassResult { token, sitekey }.
 */
async function bypassTurnstile({
  apiKey = config.turnstile.apiKey,
  sitekey,
  url,
  proxy,
  action,
  cdata,
  apiUrl = config.turnstile.apiUrl,
  timeoutMs = config.turnstile.solveTimeoutMs,
  retries = config.turnstile.retries,
}) {
  if (!apiKey) {
    throw new TurnstileError(
      "No solver key configured. Set PEAK_API_KEY (free solves at https://peak.fo) " +
        "to enable automatic Turnstile bypass."
    );
  }

  const body = JSON.stringify(buildPayload({ sitekey, url, proxy, action, cdata }));
  let lastError = null;

  for (let attempt = 1; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(apiUrl, {
        method: "POST",
        signal: controller.signal,
        headers: { "X-API-Key": apiKey, "Content-Type": "application/json" },
        body,
      });
      const data = await response.json().catch(() => ({}));

      if (!response.ok || !data.success) {
        throw new TurnstileError(
          data.error || `Solver API failed with HTTP ${response.status}`
        );
      }
      const token = (data.data || {}).token;
      if (!token) throw new TurnstileError("Solver response missing data.token");
      return { token, sitekey, raw: data };
    } catch (error) {
      lastError = error;
      if (error.name === "AbortError") {
        lastError = new TurnstileError("Solver request timed out.", 504);
      }
      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, 2_000 * attempt)); // linear backoff, like upstream
        continue;
      }
    } finally {
      clearTimeout(timer);
    }
  }

  throw lastError instanceof TurnstileError
    ? lastError
    : new TurnstileError(`Turnstile solve failed after ${retries} attempts: ${lastError?.message}`);
}

/** One call: discover the sitekey on a fetched page, then solve it. */
async function tokenForPage(html, pageUrl, options = {}) {
  const sitekey = findSitekey(html);
  if (!sitekey) throw new TurnstileError("No Turnstile sitekey found on the page.");
  const action = findAction(html);
  return bypassTurnstile({ sitekey, url: pageUrl, action, ...options });
}

/**
 * Full bypass: detect the challenge, solve it, then replay the original
 * request with `cf-turnstile-response` injected (GET query param or form POST)
 * and the clearance cookies from the shared jar. Returns
 * { response, url, html } for the real page.
 */
async function solveAndReplay(targetUrl, html, jar, deadlineAt, options = {}) {
  const { token, sitekey } = await tokenForPage(html, targetUrl, options);

  // Replay exactly like a browser that just completed the widget.
  const replayUrl = new URL(targetUrl);
  replayUrl.searchParams.set("cf-turnstile-response", token);

  const { response, url } = await safeFetch(replayUrl.href, {
    jar,
    deadlineAt,
    headers: { "Referer": targetUrl },
  });
  const finalHtml = await readLimited(response);

  if (looksLikeChallenge(finalHtml, response)) {
    throw new TurnstileError(
      "Solved the challenge but the host still gated the page " +
        "(managed challenge requires a real browser session)."
    );
  }

  return { response, url, html: finalHtml, token, sitekey };
}

module.exports = {
  TurnstileError,
  looksLikeChallenge,
  findSitekey,
  findAction,
  buildPayload,
  bypassTurnstile,
  tokenForPage,
  solveAndReplay,
};
