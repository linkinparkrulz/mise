// PayNym.rs lookup. paynym.rs runs the same API the historical Samourai server
// exposed, and offers both a clearnet host and a Tor onion. We prefer the onion
// (the box already has a SOCKS proxy for the connection gate, and it keeps the
// lookup inside Tor), falling back to clearnet.
//
// The call is POST {base}/api/v1/nym  body {"nym": "<payment code>"} and the
// response carries the registered nym label. This resolution is ALWAYS
// best-effort: any failure returns null and callers must carry on, because a
// paynym.rs outage must never block a submission or an approval.
import { socks5Connect, PROBE_CFG } from "./probe.mjs";

// Override via env if the onion address changes.
const PAYNYM_ONION = process.env.PAYNYM_ONION
  || "http://paynym25chftmsywv4v2r67agbrr62lcxagsf4tymbzpeeucucy2ivad.onion";
const PAYNYM_CLEARNET = process.env.PAYNYM_CLEARNET || "https://paynym.rs";

// Pull the human label out of whatever shape the API returns. The legacy API
// nests it under codes[].claimed / nymName; we probe a few known keys so a
// minor schema change degrades to "not found" rather than a wrong value.
function extractNym(obj) {
  if (!obj || typeof obj !== "object") return null;
  const direct = obj.nymName || obj.nym_name || obj.nym;
  if (typeof direct === "string" && direct.length) return direct;
  if (Array.isArray(obj.codes) && obj.codes[0] && typeof obj.codes[0].claimed === "string") return obj.codes[0].claimed;
  return null;
}

// Minimal HTTP POST over a SOCKS5 stream (onion), reading the JSON body.
//
// `headers` carries paynym.rs's auth-token on the calls that need it. Plain
// HTTP on port 80, no TLS: the onion IS the authentication and the encryption,
// and wrapping TLS around it would only add a certificate to get wrong.
function postOverTor(onionUrl, path, jsonBody, timeoutMs, headers = {}) {
  return new Promise(async (resolve) => {
    let socket;
    try {
      const u = new URL(onionUrl);
      socket = await socks5Connect(PROBE_CFG.proxyHost, PROBE_CFG.proxyPort, u.hostname, +(u.port || 80), timeoutMs);
    } catch { return resolve(null); }
    const body = Buffer.from(JSON.stringify(jsonBody), "utf8");
    const host = new URL(onionUrl).hostname;
    const extra = Object.entries(headers)
      .map(([k, v]) => `${k}: ${String(v).replace(/[\r\n]/g, "")}\r\n`).join("");
    const req =
      `POST ${path} HTTP/1.0\r\nHost: ${host}\r\nContent-Type: application/json\r\n` +
      extra + `Content-Length: ${body.length}\r\nConnection: close\r\n\r\n`;
    let buf = "";
    const done = (v) => { try { socket.destroy(); } catch {} resolve(v); };
    const timer = setTimeout(() => done(null), timeoutMs);
    socket.on("data", (d) => { buf += d.toString("utf8"); });
    socket.on("close", () => {
      clearTimeout(timer);
      const i = buf.indexOf("\r\n\r\n");
      if (i < 0) return resolve(null);
      try { resolve(JSON.parse(buf.slice(i + 4))); } catch { resolve(null); }
    });
    socket.on("error", () => done(null));
    socket.write(req + body.toString("utf8"));
  });
}

async function postClearnet(base, paymentCode, timeoutMs) {
  if (typeof fetch !== "function") return null;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const r = await fetch(base + "/api/v1/nym", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ nym: paymentCode }),
      signal: ctrl.signal,
    });
    clearTimeout(t);
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

// Fetch the raw nym document (codes[], nymName, ...) for a handle or payment
// code, Tor first. Returns the parsed object or null. Never throws.
export async function fetchNymInfo(nymOrCode, { timeoutMs = 20000, preferTor = true } = {}) {
  if (!nymOrCode) return null;
  let obj = null;
  if (preferTor) obj = await postOverTor(PAYNYM_ONION, "/api/v1/nym", { nym: nymOrCode }, timeoutMs);
  if (!obj) obj = await postClearnet(PAYNYM_CLEARNET, nymOrCode, timeoutMs);
  return obj && typeof obj === "object" ? obj : null;
}

// Every BIP47 code variant registered for a PayNym (segwit + legacy), because
// the wallet may sign Auth47 with either. [] when unresolvable.
export async function fetchNymCodes(nymOrCode, opts) {
  const info = await fetchNymInfo(nymOrCode, opts);
  return Array.isArray(info?.codes) ? info.codes.filter((c) => c && typeof c.code === "string") : [];
}

// Resolve a payment code to its registered PayNym label, or null. Never throws.
export async function resolvePayNym(paymentCode, opts) {
  const name = extractNym(await fetchNymInfo(paymentCode, opts));
  if (!name) return null;
  return name.startsWith("+") ? name : "+" + name;
}

// ---- registering THIS shop's own payment codes ------------------------------
//
// Everything above is a best-effort lookup of somebody else's nym, and falls
// back to clearnet when Tor cannot answer. What follows must not.
//
// Registering the shop's own codes over clearnet would announce this
// storefront's payment codes to paynym.rs from the box's real IP address. For
// an onion-only shop that is the one disclosure there is no recovering from:
// the codes are on the site, so the association is "this hidden service runs at
// this IP". A lookup that fails costs a missing avatar. A registration that
// falls back costs the operator their location. So these are Tor or nothing,
// and an unreachable proxy means the claim waits for the next attempt.
//
// The sequence is paynym-bot's (src/paynymrs.ts), which is already proven
// against the live directory:
//
//   POST /api/v1/create  {code}                 publish the code (idempotent)
//   POST /api/v1/token   {code}                 -> {token}, 24h
//   POST /api/v1/claim   {signature}            + auth-token header
//   POST /api/v1/follow  {target, signature}    + auth-token header
//
// The signature is a Bitcoin signed message over the token, made by the
// notification key. This process never holds that key: it asks the gateway,
// which refuses to sign anything that is not token-shaped. See
// gateway/identity.ts signToken for why that refusal matters.

class PaynymError extends Error {}

/** One authenticated-or-not POST to the directory, over Tor only. */
async function apiCall(path, body, { timeoutMs = 20000, authToken = null } = {}) {
  const headers = authToken ? { "auth-token": authToken } : {};
  const out = await postOverTor(PAYNYM_ONION, `/api/v1${path}`, body, timeoutMs, headers);
  if (!out) {
    throw new PaynymError(
      `paynym.rs did not answer ${path} over Tor. This call deliberately does not fall back to ` +
      "clearnet, because that would announce this shop's payment codes from the box's own IP. " +
      "Check that the SOCKS proxy is up and try again.");
  }
  return out;
}

/** Publish a payment code. Safe to repeat: the directory treats it as upsert. */
export const createNym = (paymentCode, opts) => apiCall("/create", { code: paymentCode }, opts);

/** A 24h auth token for a payment code. We use it immediately and discard it. */
export async function tokenFor(paymentCode, opts) {
  const out = await apiCall("/token", { code: paymentCode }, opts);
  const token = out && out.token;
  if (typeof token !== "string" || !token) throw new PaynymError("paynym.rs /token returned no token");
  return token;
}

/** Claim a published code by proving the notification key signed its token. */
export const claimNym = (signature, authToken, opts) =>
  apiCall("/claim", { signature }, { ...opts, authToken });

/**
 * Follow another payment code.
 *
 * Chain-agnostic: a testnet target is as valid as a mainnet one, which is what
 * makes a testnet4 rehearsal produce a follow against the wallet being tested
 * with rather than against the operator's mainnet identity.
 */
export const followNym = (target, signature, authToken, opts) =>
  apiCall("/follow", { target, signature }, { ...opts, authToken });

export { PaynymError };
