// Claiming the shop wallet's PayNyms, and following the operator with them.
//
// WHY THIS LIVES HERE AND NOT IN THE GATEWAY. The gateway holds the seed and
// has no network access, deliberately — that is the property that makes a
// compromised web server survivable. So the dance is split at the only point
// that needs a key: this process talks to the directory, and asks the gateway
// for one signature over a token. The gateway refuses to sign anything that is
// not token-shaped, so this process cannot use that channel to mint an invoice
// address record (gateway/identity.ts, signToken).
//
// ONE NYM PER NETWORK, BOTH AT SETUP. A PayNym is a function of the payment
// code. The shop's two networks have different codes, so they are two
// independent identities with different names and different avatars, and
// neither waits on the other or on which network is currently active. First run
// claims both.
//
// Best-effort throughout. The directory is a social service; a shop whose
// operator would rather not appear in it, or whose Tor is down, must still sell
// things. Every failure here is reported and none is fatal.

import path from "node:path";
import { createNym, tokenFor, claimNym, followNym, PaynymError } from "./paynym.mjs";
import { PROBE_CFG } from "./probe.mjs";

/**
 * Claim one network's payment code.
 *
 * `ask` is the gateway client, injected rather than imported so the suite can
 * drive this against a mock socket. Returns what the directory said; throws
 * only when the directory or Tor did.
 */
export async function claimOne(ask, network, paymentCode, opts = {}) {
  // Idempotent by construction: /create is an upsert, and a code that is
  // already claimed comes back claimed. So a retry after a Tor outage is the
  // whole recovery story, and there is no half-claimed state to repair.
  const created = await createNym(paymentCode, opts);
  const token = await tokenFor(paymentCode, opts);

  const signed = await ask({ op: "paynym-sign", network, token });
  if (signed.error) throw new PaynymError(`the gateway would not sign the token: ${signed.error}`);

  const claimed = await claimNym(signed.signature, token, opts);
  const nymName = claimed.nymName || created.nymName || null;
  const nymId = claimed.nymId ?? claimed.nymID ?? created.nymId ?? created.nymID ?? null;
  if (!nymName) {
    throw new PaynymError(
      `paynym.rs claimed ${network} but returned no nym name: ${JSON.stringify(claimed).slice(0, 200)}`);
  }
  const recorded = await ask({ op: "record-nym", network, nymName, nymId });
  if (recorded.error) throw new PaynymError(`claimed ${nymName} but could not record it: ${recorded.error}`);
  return { network, nymName, nymId, claimed: claimed.claimed === true };
}

/**
 * Follow a payment code as one network's nym.
 *
 * Separate from the claim because it needs a receiver, and at setup there is
 * none. /follow is chain-agnostic, so the network here selects which of the
 * shop's identities does the following, not what the target may be.
 */
export async function followAs(ask, network, paymentCode, target, opts = {}) {
  const token = await tokenFor(paymentCode, opts);
  const signed = await ask({ op: "paynym-sign", network, token });
  if (signed.error) throw new PaynymError(`the gateway would not sign the token: ${signed.error}`);
  const out = await followNym(target, signed.signature, token, opts);
  // Reported as it arrived rather than reduced to a boolean: this endpoint is
  // the one part of the sequence not already proven against the live directory,
  // so the first real run needs to show exactly what came back.
  return { network, target, response: out };
}

/** Mirror a nym's avatar, so the panel and its QR have a face to show. */
export async function mirrorAvatar(paymentCode, dataDir) {
  const { fetchAvatar } = await import("../scripts/update.mjs");
  await fetchAvatar(paymentCode, {
    proxyHost: PROBE_CFG.proxyHost, proxyPort: PROBE_CFG.proxyPort,
    destDir: path.join(dataDir, "avatars"),
  });
}

/**
 * Claim every network that has no nym yet.
 *
 * Runs per network and keeps going after a failure: one network's directory
 * trouble must not leave the other unclaimed, and they are independent
 * identities anyway. Returns a row per network so the panel can say which
 * worked and why the rest did not.
 */
export async function claimMissing(ask, identity, dataDir, opts = {}) {
  /** @type {Array<{network:string,nymName?:string|null,nymId?:string|null,claimed?:boolean,skipped?:string,error?:string}>} */
  const rows = [];
  for (const [network, block] of Object.entries(identity.networks || {})) {
    if (block.nymName) { rows.push({ network, nymName: block.nymName, skipped: "already claimed" }); continue; }
    try {
      const got = await claimOne(ask, network, block.paymentCode, opts);
      await mirrorAvatar(block.paymentCode, dataDir).catch(() => {});
      rows.push(got);
    } catch (e) {
      rows.push({ network, error: e.message });
    }
  }
  return rows;
}
