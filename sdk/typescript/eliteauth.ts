export const ELITEAUTH_SIGNING_PUBLIC_KEY = "Yo7wBxsz8mCN6LX89Ja0H3pNlcLXJHrJ50u5BtZuakQ";
export const ELITEAUTH_SIGNING_KEY_ID = "eliteauth-ed25519-2026-01";

export interface EliteAuthOptions {
  apiUrl: string;
  appId: string;
  version: string;
  publicKey?: string;
  integritySha256?: string;
  sdkVersion?: string;
  maxServerSkewSeconds?: number;
}

export interface EliteAuthResult {
  success: boolean;
  valid?: boolean;
  error?: string;
  message?: string;
  session?: { token?: string; challenge?: string; expires_at?: string };
  application?: Record<string, unknown>;
  license?: Record<string, unknown>;
  httpStatus: number;
  requestId: string;
}

interface SignedPayload {
  protocol: string;
  request_id: string;
  server_time: number;
  nonce: string;
  data: Record<string, unknown>;
}

export class EliteAuthClient {
  private readonly apiUrl: string;
  private readonly appId: string;
  private readonly version: string;
  private readonly publicKey: string;
  private readonly integritySha256: string;
  private readonly sdkVersion: string;
  private readonly maxServerSkewSeconds: number;
  private sessionToken: string | null = null;
  private challenge: string | null = null;
  private verificationKeyPromise: Promise<CryptoKey> | null = null;

  constructor(options: EliteAuthOptions) {
    if (!options.apiUrl || !options.appId || !options.version) {
      throw new Error("apiUrl, appId and version are required");
    }
    this.apiUrl = options.apiUrl.replace(/\/+$/, "");
    this.appId = options.appId;
    this.version = options.version;
    this.publicKey = options.publicKey || ELITEAUTH_SIGNING_PUBLIC_KEY;
    this.integritySha256 = normalizeHash(options.integritySha256 || "");
    this.sdkVersion = options.sdkVersion || "ts-1.1.0";
    this.maxServerSkewSeconds = options.maxServerSkewSeconds || 300;
  }

  async activate(licenseKey: string, hwid: string): Promise<EliteAuthResult> {
    const nonce = randomBase64Url(24);
    const response = await this.postSigned("/v1/license/activate", {
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
      if (!this.sessionToken || !this.challenge) throw new Error("Signed activation response is missing session state");
    }
    return response;
  }

  async checkSession(hwid: string): Promise<EliteAuthResult> {
    if (!this.sessionToken || !this.challenge) throw new Error("Call activate() before checkSession()");
    const nonce = randomBase64Url(24);
    const response = await this.postSigned("/v1/session/check", {
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

  clearSession(): void {
    this.sessionToken = null;
    this.challenge = null;
  }

  private async postSigned(path: string, body: Record<string, unknown>, expectedNonce: string): Promise<EliteAuthResult> {
    const response = await fetch(`${this.apiUrl}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      cache: "no-store",
      body: JSON.stringify(body),
    });
    const envelope = await response.json() as Record<string, unknown>;
    const payload = await this.verifyEnvelope(envelope, expectedNonce);
    const data = payload.data as unknown as EliteAuthResult;
    return { ...data, httpStatus: response.status, requestId: payload.request_id };
  }

  private async verifyEnvelope(envelope: Record<string, unknown>, expectedNonce: string): Promise<SignedPayload> {
    if (envelope.key_id !== ELITEAUTH_SIGNING_KEY_ID || envelope.algorithm !== "Ed25519") {
      throw new Error("Unexpected EliteAuth signing key or algorithm");
    }
    if (typeof envelope.payload !== "string" || typeof envelope.signature !== "string") {
      throw new Error("EliteAuth response is not a signed envelope");
    }
    const payloadBytes = base64UrlToBytes(envelope.payload);
    const signatureBytes = base64UrlToBytes(envelope.signature);
    const valid = await crypto.subtle.verify("Ed25519", await this.verificationKey(), signatureBytes, payloadBytes);
    if (!valid) throw new Error("EliteAuth response signature verification failed");
    const payload = JSON.parse(new TextDecoder().decode(payloadBytes)) as SignedPayload;
    if (payload.protocol !== "eliteauth-signed-v1") throw new Error("Unsupported EliteAuth protocol");
    if (payload.nonce !== expectedNonce) throw new Error("EliteAuth response nonce mismatch");
    if (!Number.isInteger(payload.server_time) || Math.abs(unixTime() - payload.server_time) > this.maxServerSkewSeconds) {
      throw new Error("EliteAuth response timestamp is outside the allowed window");
    }
    return payload;
  }

  private verificationKey(): Promise<CryptoKey> {
    this.verificationKeyPromise ||= crypto.subtle.importKey(
      "raw",
      base64UrlToBytes(this.publicKey),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return this.verificationKeyPromise;
  }
}

function unixTime(): number { return Math.floor(Date.now() / 1000); }
function normalizeHash(value: string): string {
  const hash = value.trim().toLowerCase();
  if (!hash) return "";
  if (!/^[a-f0-9]{64}$/.test(hash)) throw new Error("integritySha256 must be a 64-character SHA-256 value");
  return hash;
}
function randomBase64Url(length: number): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}
function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}
