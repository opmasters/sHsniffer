"use strict";

/**
 * SSRF-safe URL validation. Every outbound request the sniffer makes is
 * funnelled through validateUrl(), which resolves DNS first and rejects
 * private / reserved / loopback ranges so the service can never be used to
 * scan Render's internal network.
 */

const ipaddr = require("ipaddr.js");
const dns = require("node:dns").promises;
const net = require("node:net");
const config = require("./config");

class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ValidationError";
    this.statusCode = 400;
  }
}

function isPublicAddress(address) {
  try {
    const parsed = ipaddr.process(address);
    if (parsed.range() !== "unicast") return false;

    // Extra belt-and-braces for ranges ipaddr classifies as unicast but that
    // are still carrier-grade NAT / benchmark space.
    const kind = parsed.kind();
    if (kind === "ipv4") {
      const [a] = parsed.toByteArray();
      if (a === 100 && parsed.toString().startsWith("100.64.")) return false; // CGNAT
      if (parsed.toString().startsWith("198.18.")) return false;              // benchmarking
    }
    return true;
  } catch {
    return false;
  }
}

const dnsCache = new Map(); // hostname -> { expires, addresses }

async function resolveAddresses(hostname) {
  const now = Date.now();
  const hit = dnsCache.get(hostname);
  if (hit && hit.expires > now) return hit.addresses;

  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new ValidationError("The target hostname could not be resolved.");
  }
  if (!addresses.length) {
    throw new ValidationError("The target hostname could not be resolved.");
  }

  dnsCache.set(hostname, { expires: now + 30_000, addresses });
  if (dnsCache.size > 2_000) dnsCache.clear();
  return addresses;
}

/**
 * Parse + vet a URL. Returns a WHATWG URL object.
 */
async function validateUrl(value) {
  let url;
  try {
    url = new URL(String(value));
  } catch {
    throw new ValidationError("The supplied link is not a valid URL.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new ValidationError("Only HTTP and HTTPS links are supported.");
  }
  if (url.username || url.password) {
    throw new ValidationError("URLs containing credentials are not supported.");
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();

  if (
    !hostname ||
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname === "metadata.google.internal"
  ) {
    throw new ValidationError("Private and local network hosts are not allowed.");
  }

  if (!config.allowPrivateNetworks) {
    if (net.isIP(hostname)) {
      if (!isPublicAddress(hostname)) {
        throw new ValidationError("Private or reserved IP addresses are not allowed.");
      }
    } else {
      const addresses = await resolveAddresses(hostname);
      if (addresses.some((item) => !isPublicAddress(item.address))) {
        throw new ValidationError(
          "The hostname resolves to a private or reserved address."
        );
      }
    }
  }

  url.hash = "";
  return url;
}

module.exports = { validateUrl, isPublicAddress, ValidationError };
