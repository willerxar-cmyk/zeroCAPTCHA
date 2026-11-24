// zeroCAPTCHA © 2026 Willer Xavier Reis and SID6. See LICENSE.
"use strict";
(() => {
  var CHALLENGE_PURPOSES = ["login", "register", "recovery", "booking"];
  var MAX_SOLVE_ATTEMPTS = 1 << 20;
  var SOLVE_TIMEOUT_MS = 9e4;
  function b64ToBytes(b64) {
    if (typeof Buffer !== "undefined") {
      return new Uint8Array(Buffer.from(b64, "base64"));
    }
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  function le64Bytes(value) {
    const bytes = new Uint8Array(8);
    const hi = Math.floor(value / 4294967296);
    const lo = value % 4294967296;
    const view = new DataView(bytes.buffer);
    view.setUint32(0, lo, true);
    view.setUint32(4, hi, true);
    return bytes;
  }
  function bytesToHex(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      out += bytes[i].toString(16).padStart(2, "0");
    }
    return out;
  }
  async function deriveKey(salt, counter, cost, keyLengthBytes = 32) {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      le64Bytes(counter),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: Math.max(1, cost) },
      keyMaterial,
      keyLengthBytes * 8
    );
    return new Uint8Array(bits);
  }
  async function solveChallenge(challenge, opts) {
    const maxAttempts = opts?.maxAttempts ?? MAX_SOLVE_ATTEMPTS;
    const timeoutMs = opts?.timeoutMs ?? SOLVE_TIMEOUT_MS;
    const deadline = Date.now() + timeoutMs;
    const salt = b64ToBytes(challenge.salt);
    const prefix = challenge.prefix.toLowerCase();
    for (let counter = 0; counter < maxAttempts; counter++) {
      if (counter % 256 === 0 && Date.now() > deadline) {
        throw new Error("zerocaptcha: solve timed out");
      }
      const key = await deriveKey(salt, counter, challenge.cost);
      const hexKey = bytesToHex(key);
      if (hexKey.startsWith(prefix)) {
        return { challenge, counter, key: hexKey };
      }
    }
    throw new Error("zerocaptcha: no solution found within attempt cap");
  }
  function validateChallengeShape(c) {
    if (!c.id || !c.alg || !c.salt || !c.prefix || !c.sig) {
      return "challenge missing required fields";
    }
    if (c.alg !== "S6-PBKDF2-SHA256") return "challenge algorithm is unsupported by this widget";
    if (!Number.isSafeInteger(c.cost) || c.cost < 1 || c.cost > 1e6) return "challenge cost out of range";
    if (c.kind !== "proof_of_work") return "challenge kind is not solvable by the human widget";
    if (!/^[0-9a-f]{64}$/.test(c.client_binding)) return "challenge client binding invalid";
    if (c.expires_at < Math.floor(Date.now() / 1e3)) return "challenge expired";
    if (!/^[0-9a-f]+$/.test(c.prefix)) return "challenge prefix must be hex";
    if (!CHALLENGE_PURPOSES.includes(c.purpose)) {
      return "challenge purpose invalid";
    }
    if (c.precision !== void 0 && (!c.precision || !Number.isSafeInteger(c.precision.hold_ms) || !Number.isSafeInteger(c.precision.release_window_ms) || c.precision.hold_ms <= 0 || c.precision.release_window_ms <= 0)) return "challenge precision timing invalid";
    return null;
  }

  self.onmessage = async (event) => {
    const { id, challenge } = event.data;
    try {
      const shapeError = validateChallengeShape(challenge);
      if (shapeError) throw new Error(shapeError);
      const solution = await solveChallenge(challenge);
      const payload = { id, ok: true, solution };
      self.postMessage(payload);
    } catch (error) {
      const payload = {
        id,
        ok: false,
        error: error instanceof Error ? error.message : String(error)
      };
      self.postMessage(payload);
    }
  };
})();
