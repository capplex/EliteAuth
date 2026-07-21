export const ELITEAUTH_SIGNING_PUBLIC_KEY = "Yo7wBxsz8mCN6LX89Ja0H3pNlcLXJHrJ50u5BtZuakQ";
export const ELITEAUTH_SIGNING_KEY_ID = "eliteauth-ed25519-2026-01";

export class EliteAuthClient {
  constructor(apiUrl, appId, version, options = {}) {
    if (!apiUrl || !appId || !version) throw new Error("apiUrl, appId and version are required");
    this.apiUrl = String(apiUrl).replace(/\/+$/, "");
    this.appId = appId;
    this.version = version;
    this.publicKey = options.publicKey || ELITEAUTH_SIGNING_PUBLIC_KEY;
    this.integritySha256 = normalizeHash(options.integritySha256 || "");
    this.sdkVersion = options.sdkVersion || "js-1.1.0";
    this.maxServerSkewSeconds = options.maxServerSkewSeconds || 300;
    this.sessionToken = null;
    this.challenge = null;
    this.verificationKeyPromise = null;
  }

  async activate(licenseKey, hwid) {
    const nonce = randomBase64Url(24);
    const response = await this.#postSigned("/v1/license/activate", {
      app_id: this.appId,
      license_key: licenseKey,
      hwid,
      version: this.version,
      sdk_version: this.sdkVersion,
      integrity_sha256: this.integritySha256 || null,
      timestamp: unixTime(),
      nonce,
    }, nonce);

    if (response.success) {
      this.sessionToken = response.session?.token || null;
      this.challenge = response.session?.challenge || null;
      if (!this.sessionToken || !this.challenge) throw new Error("Signed activation response did not include a session token and challenge");
    }
    return response;
  }

  async checkSession(hwid) {
    if (!this.sessionToken || !this.challenge) throw new Error("No active EliteAuth session. Call activate() first.");
    const nonce = randomBase64Url(24);
    const response = await this.#postSigned("/v1/session/check", {
      app_id: this.appId,
      session_token: this.sessionToken,
      challenge: this.challenge,
      hwid,
      sdk_version: this.sdkVersion,
      integrity_sha256: this.integritySha256 || null,
      timestamp: unixTime(),
      nonce,
    }, nonce);

    if (response.success && response.valid) {
      const nextChallenge = response.session?.challenge;
      if (!nextChallenge) throw new Error("Signed session response did not rotate the challenge");
      this.challenge = nextChallenge;
    }
    return response;
  }

  clearSession() {
    this.sessionToken = null;
    this.challenge = null;
  }

  async #postSigned(path, body, expectedNonce) {
    const httpResponse = await fetch(`${this.apiUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      cache: "no-store",
      body: JSON.stringify(body),
    });

    const envelope = await httpResponse.json().catch(() => {
      throw new Error("EliteAuth returned invalid JSON");
    });
    const payload = await this.#verifyEnvelope(envelope, expectedNonce);
    const data = payload.data;
    if (!data || typeof data !== "object") throw new Error("Signed EliteAuth payload is missing data");
    return { ...data, httpStatus: httpResponse.status, requestId: payload.request_id };
  }

  async #verifyEnvelope(envelope, expectedNonce) {
    if (!envelope || envelope.key_id !== ELITEAUTH_SIGNING_KEY_ID || envelope.algorithm !== "Ed25519") {
      throw new Error("EliteAuth response used an unexpected signing key or algorithm");
    }
    if (typeof envelope.payload !== "string" || typeof envelope.signature !== "string") {
      throw new Error("EliteAuth response is not a signed envelope");
    }

    const payloadBytes = base64UrlToBytes(envelope.payload);
    const signatureBytes = base64UrlToBytes(envelope.signature);
    const key = await this.#verificationKey();
    const valid = await crypto.subtle.verify("Ed25519", key, signatureBytes, payloadBytes);
    if (!valid) throw new Error("EliteAuth response signature verification failed");

    const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
    if (payload.protocol !== "eliteauth-signed-v1") throw new Error("Unsupported EliteAuth signed-response protocol");
    if (payload.nonce !== expectedNonce) throw new Error("EliteAuth response nonce mismatch");
    if (!Number.isInteger(payload.server_time) || Math.abs(unixTime() - payload.server_time) > this.maxServerSkewSeconds) {
      throw new Error("EliteAuth response timestamp is outside the allowed window");
    }
    return payload;
  }

  async #verificationKey() {
    if (!this.verificationKeyPromise) {
      this.verificationKeyPromise = crypto.subtle.importKey(
        "raw",
        base64UrlToBytes(this.publicKey),
        { name: "Ed25519" },
        false,
        ["verify"]
      );
    }
    return this.verificationKeyPromise;
  }
}

function unixTime() {
  return Math.floor(Date.now() / 1000);
}

function normalizeHash(value) {
  const hash = String(value || "").trim().toLowerCase();
  if (!hash) return "";
  if (!/^[a-f0-9]{64}$/.test(hash)) throw new Error("integritySha256 must be a 64-character SHA-256 hex value");
  return hash;
}

function randomBase64Url(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlToBytes(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}
