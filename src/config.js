"use strict";

/**
 * Central configuration. Everything is tunable through environment variables
 * so the same code runs on Render free tier or a paid instance without
 * changes.
 */

const num = (name, fallback) => {
  const value = Number(process.env[name]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
};

const bool = (name, fallback) => {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  return ["1", "true", "yes", "on"].includes(String(raw).toLowerCase());
};

const config = {
  port: Number(process.env.PORT) || 10000, // Render injects PORT

  // ---- Fetch budget -------------------------------------------------------
  maxBytes: num("MAX_BYTES", 4 * 1024 * 1024),        // per-document inspection cap
  timeoutMs: num("TIMEOUT_MS", 12_000),               // per-request deadline
  totalBudgetMs: num("TOTAL_BUDGET_MS", 30_000),      // whole-sniff deadline
  maxRedirects: num("MAX_REDIRECTS", 6),
  maxDepth: num("MAX_DEPTH", 2),                      // nested iframe/player recursion
  maxResults: num("MAX_RESULTS", 200),
  concurrency: num("CONCURRENCY", 6),                 // parallel candidate fetches

  // ---- Cache --------------------------------------------------------------
  cacheTtlMs: num("CACHE_TTL_MS", 60_000),
  negativeCacheTtlMs: num("NEGATIVE_CACHE_TTL_MS", 15_000),
  cacheMaxEntries: num("CACHE_MAX_ENTRIES", 500),

  // ---- Rate limiting ------------------------------------------------------
  rateLimitPerMinute: num("RATE_LIMIT_PER_MINUTE", 30),

  // ---- Turnstile solving (Peak API, cloudflare-turnstile-bypass protocol) -
  turnstile: {
    enabled: bool("TURNSTILE_ENABLED", true),
    apiKey: process.env.PEAK_API_KEY || "",
    apiUrl: process.env.PEAK_API_URL || "https://api.peak.fo/solve",
    solveTimeoutMs: num("TURNSTILE_SOLVE_TIMEOUT_MS", 60_000),
    retries: num("TURNSTILE_RETRIES", 2),
  },

  // ---- SSRF guard ---------------------------------------------------------
  allowPrivateNetworks: bool("ALLOW_PRIVATE_NETWORKS", false),

  userAgent:
    process.env.USER_AGENT ||
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 VidSniffer/2.0",
};

module.exports = config;
