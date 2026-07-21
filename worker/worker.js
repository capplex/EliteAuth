const API_VERSION = "1.1.0";
const PROTOCOL = "eliteauth-signed-v1";
const SIGNING_KEY_ID = "eliteauth-ed25519-2026-01";
const SIGNING_PUBLIC_KEY = "Yo7wBxsz8mCN6LX89Ja0H3pNlcLXJHrJ50u5BtZuakQ";
const SESSION_DURATION_MS = 30 * 60 * 1000;
const REQUEST_WINDOW_SECONDS = 120;

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = normalizePath(url.pathname);

    try {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders() });
      }

      if (pathname === "/" && request.method === "GET") {
        return json({
          success: true,
          service: "EliteAuth API",
          status: "online",
          version: API_VERSION,
          anti_tamper: {
            protocol: PROTOCOL,
            response_signing: "Ed25519",
            replay_protection: true,
            integrity_allowlist: true,
          },
          endpoints: {
            health: "GET /health",
            keys: "GET /v1/keys",
            activate: "POST /v1/license/activate",
            session_check: "POST /v1/session/check",
          },
        });
      }

      if (pathname === "/health" && request.method === "GET") {
        return json({
          success: true,
          service: "EliteAuth API",
          status: "healthy",
          version: API_VERSION,
          timestamp: new Date().toISOString(),
        });
      }

      if (pathname === "/v1/keys" && request.method === "GET") {
        return json({
          success: true,
          key_id: SIGNING_KEY_ID,
          algorithm: "Ed25519",
          public_key: SIGNING_PUBLIC_KEY,
          note: "Pin this key in the SDK. Do not fetch it dynamically for each authentication request.",
        });
      }

      validateEnvironment(env);

      if (pathname === "/v1/license/activate") {
        if (request.method !== "POST") return methodNotAllowed(env, "POST, OPTIONS");
        const parsed = await readJsonBody(request);
        if (!parsed.ok) return signedError(env, parsed.error, 400, "");
        return activateLicense(request, env, parsed.data);
      }

      if (pathname === "/v1/session/check") {
        if (request.method !== "POST") return methodNotAllowed(env, "POST, OPTIONS");
        const parsed = await readJsonBody(request);
        if (!parsed.ok) return signedError(env, parsed.error, 400, "");
        return checkSession(request, env, parsed.data);
      }

      return json({ success: false, error: "Route not found" }, 404);
    } catch (error) {
      console.error("Unhandled Worker error:", error);
      try {
        return await signedError(env, "Internal server error", 500, "");
      } catch {
        return json({ success: false, error: "Internal server error" }, 500);
      }
    }
  },
};

async function activateLicense(request, env, body) {
  const appId = cleanString(body.app_id);
  const licenseKey = cleanString(body.license_key);
  const hwid = cleanString(body.hwid);
  const version = cleanString(body.version);
  const sdkVersion = cleanString(body.sdk_version) || "unknown";
  const nonce = cleanString(body.nonce);
  const timestamp = Number(body.timestamp);
  const integritySha256 = normalizeSha256(body.integrity_sha256);

  if (!appId || !licenseKey || !hwid || !nonce || !Number.isFinite(timestamp)) {
    return signedError(env, "app_id, license_key, hwid, nonce and timestamp are required", 400, nonce);
  }

  const requestSecurityError = validateRequestWindow(timestamp, nonce);
  if (requestSecurityError) return signedError(env, requestSecurityError, 400, nonce);

  const application = await selectOne(env, "applications", {
    app_id: `eq.${appId}`,
    select: "id,app_id,name,version,enabled,enforce_integrity,integrity_sha256",
  });

  if (!application) return signedError(env, "Application not found", 404, nonce);
  if (!application.enabled) return signedError(env, "Application disabled", 403, nonce);

  const nonceAccepted = await reserveNonce(env, application.id, nonce);
  if (!nonceAccepted) {
    await recordSecurityEvent(env, application.id, null, "replay_detected", { route: "/v1/license/activate" });
    return signedError(env, "Replay detected", 409, nonce);
  }

  const integrityError = validateIntegrity(application, integritySha256);
  if (integrityError) {
    await recordSecurityEvent(env, application.id, null, "integrity_mismatch", {
      expected: application.integrity_sha256 || null,
      received: integritySha256 || null,
      route: "/v1/license/activate",
    });
    return signedError(env, integrityError, 403, nonce);
  }

  if (version && application.version && version !== application.version) {
    return signedResponse(env, {
      success: false,
      error: "Version mismatch",
      required: application.version,
    }, 426, nonce);
  }

  const license = await selectOne(env, "licenses", {
    application_id: `eq.${application.id}`,
    key: `eq.${licenseKey}`,
    select: "id,application_id,key,status,hwid,expires_at,activated_at,duration_seconds",
  });

  if (!license) return signedError(env, "Invalid license key", 401, nonce);
  if (license.status !== "active") return signedError(env, `License is ${license.status}`, 403, nonce);

  let effectiveExpiry = license.expires_at;
  if (!effectiveExpiry && !license.hwid && Number(license.duration_seconds) > 0) {
    effectiveExpiry = new Date(Date.now() + Number(license.duration_seconds) * 1000).toISOString();
  }
  if (isExpired(effectiveExpiry)) return signedError(env, "License expired", 403, nonce);
  if (license.hwid && license.hwid !== hwid) return signedError(env, "HWID mismatch", 403, nonce);

  if (!license.hwid) {
    const update = {
      hwid,
      activated_at: new Date().toISOString(),
    };
    if (effectiveExpiry && !license.expires_at) update.expires_at = effectiveExpiry;

    const bound = await updateRowsReturning(env, "licenses", {
      id: `eq.${license.id}`,
      hwid: "is.null",
    }, update);

    if (!bound.length) {
      const reread = await selectOne(env, "licenses", {
        id: `eq.${license.id}`,
        select: "id,hwid,expires_at",
      });
      if (!reread || reread.hwid !== hwid) {
        return signedError(env, "License was activated on another device", 403, nonce);
      }
      effectiveExpiry = reread.expires_at;
    }
  }

  const sessionToken = randomBase64Url(32);
  const sessionChallenge = randomBase64Url(32);
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();

  await insertRow(env, "license_sessions", {
    application_id: application.id,
    license_id: license.id,
    token_hash: await sha256Hex(sessionToken),
    challenge_hash: await sha256Hex(sessionChallenge),
    hwid,
    integrity_sha256: integritySha256 || null,
    sdk_version: sdkVersion,
    ip_address: request.headers.get("CF-Connecting-IP"),
    user_agent: request.headers.get("User-Agent"),
    expires_at: expiresAt,
    last_seen_at: new Date().toISOString(),
  });

  return signedResponse(env, {
    success: true,
    message: "License authenticated",
    application: {
      app_id: application.app_id,
      name: application.name,
      version: application.version,
      integrity_enforced: Boolean(application.enforce_integrity),
    },
    session: {
      token: sessionToken,
      challenge: sessionChallenge,
      expires_at: expiresAt,
    },
    license: {
      key: license.key,
      expires_at: effectiveExpiry || null,
    },
  }, 200, nonce);
}

async function checkSession(request, env, body) {
  const appId = cleanString(body.app_id);
  const sessionToken = cleanString(body.session_token);
  const challenge = cleanString(body.challenge);
  const hwid = cleanString(body.hwid);
  const sdkVersion = cleanString(body.sdk_version) || "unknown";
  const nonce = cleanString(body.nonce);
  const timestamp = Number(body.timestamp);
  const integritySha256 = normalizeSha256(body.integrity_sha256);

  if (!appId || !sessionToken || !challenge || !hwid || !nonce || !Number.isFinite(timestamp)) {
    return signedError(env, "app_id, session_token, challenge, hwid, nonce and timestamp are required", 400, nonce);
  }

  const requestSecurityError = validateRequestWindow(timestamp, nonce);
  if (requestSecurityError) return signedError(env, requestSecurityError, 400, nonce);

  const application = await selectOne(env, "applications", {
    app_id: `eq.${appId}`,
    select: "id,app_id,name,version,enabled,enforce_integrity,integrity_sha256",
  });

  if (!application) return signedError(env, "Application not found", 404, nonce);
  if (!application.enabled) return signedError(env, "Application disabled", 403, nonce);

  const nonceAccepted = await reserveNonce(env, application.id, nonce);
  if (!nonceAccepted) {
    await recordSecurityEvent(env, application.id, null, "replay_detected", { route: "/v1/session/check" });
    return signedError(env, "Replay detected", 409, nonce);
  }

  const integrityError = validateIntegrity(application, integritySha256);
  if (integrityError) {
    await recordSecurityEvent(env, application.id, null, "integrity_mismatch", {
      expected: application.integrity_sha256 || null,
      received: integritySha256 || null,
      route: "/v1/session/check",
    });
    return signedError(env, integrityError, 403, nonce);
  }

  const tokenHash = await sha256Hex(sessionToken);
  const session = await selectOne(env, "license_sessions", {
    application_id: `eq.${application.id}`,
    token_hash: `eq.${tokenHash}`,
    select: "id,application_id,license_id,hwid,expires_at,revoked_at,challenge_hash",
  });

  if (!session) return signedInvalid(env, "Invalid session", 401, nonce);
  if (session.revoked_at) return signedInvalid(env, "Session revoked", 401, nonce);
  if (isExpired(session.expires_at)) return signedInvalid(env, "Session expired", 401, nonce);
  if (session.hwid !== hwid) return signedInvalid(env, "HWID mismatch", 403, nonce);

  const suppliedChallengeHash = await sha256Hex(challenge);
  if (!timingSafeHexEqual(suppliedChallengeHash, session.challenge_hash || "")) {
    await recordSecurityEvent(env, application.id, session.license_id, "challenge_mismatch", { route: "/v1/session/check" });
    return signedInvalid(env, "Session challenge rejected", 409, nonce);
  }

  const nextChallenge = randomBase64Url(32);
  const nextChallengeHash = await sha256Hex(nextChallenge);
  const rotated = await updateRowsReturning(env, "license_sessions", {
    id: `eq.${session.id}`,
    challenge_hash: `eq.${suppliedChallengeHash}`,
    revoked_at: "is.null",
  }, {
    challenge_hash: nextChallengeHash,
    integrity_sha256: integritySha256 || null,
    sdk_version: sdkVersion,
    last_seen_at: new Date().toISOString(),
    ip_address: request.headers.get("CF-Connecting-IP"),
    user_agent: request.headers.get("User-Agent"),
  });

  if (!rotated.length) {
    await recordSecurityEvent(env, application.id, session.license_id, "challenge_replay", { route: "/v1/session/check" });
    return signedInvalid(env, "Replay or concurrent session check detected", 409, nonce);
  }

  const license = await selectOne(env, "licenses", {
    id: `eq.${session.license_id}`,
    application_id: `eq.${application.id}`,
    select: "id,status,hwid,expires_at",
  });

  if (!license) return signedInvalid(env, "License not found", 401, nonce);
  if (license.status !== "active") return signedInvalid(env, `License is ${license.status}`, 403, nonce);
  if (isExpired(license.expires_at)) return signedInvalid(env, "License expired", 403, nonce);
  if (license.hwid && license.hwid !== hwid) return signedInvalid(env, "HWID mismatch", 403, nonce);

  return signedResponse(env, {
    success: true,
    valid: true,
    expires_at: session.expires_at,
    session: {
      challenge: nextChallenge,
    },
    application: {
      app_id: application.app_id,
      name: application.name,
      version: application.version,
      integrity_enforced: Boolean(application.enforce_integrity),
    },
  }, 200, nonce);
}

function validateRequestWindow(timestamp, nonce) {
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) return "nonce must be 16-128 base64url characters";
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isInteger(timestamp)) return "timestamp must be a Unix timestamp in seconds";
  if (Math.abs(now - timestamp) > REQUEST_WINDOW_SECONDS) return "Request timestamp is outside the allowed window";
  return null;
}

function validateIntegrity(application, receivedHash) {
  if (!application.enforce_integrity) return null;
  const expected = normalizeSha256(application.integrity_sha256);
  if (!expected) return "Application integrity enforcement is enabled but no valid build hash is configured";
  if (!receivedHash) return "Build integrity hash is required";
  if (!timingSafeHexEqual(expected, receivedHash)) return "Build integrity check failed";
  return null;
}

async function reserveNonce(env, applicationId, nonce) {
  const response = await fetch(`${trimSlash(env.SUPABASE_URL)}/rest/v1/rpc/reserve_api_nonce`, {
    method: "POST",
    headers: supabaseHeaders(env),
    body: JSON.stringify({
      application_id_input: applicationId,
      nonce_input: nonce,
      expires_at_input: new Date(Date.now() + REQUEST_WINDOW_SECONDS * 2000).toISOString(),
    }),
  });
  if (!response.ok) {
    const text = await response.text();
    console.error("reserve_api_nonce error:", response.status, text);
    throw new Error(`Nonce reservation failed with ${response.status}`);
  }
  return Boolean(await response.json());
}

async function recordSecurityEvent(env, applicationId, licenseId, eventType, details) {
  try {
    await insertRow(env, "security_events", {
      application_id: applicationId,
      license_id: licenseId,
      event_type: eventType,
      details,
    });
  } catch (error) {
    console.error("Security event logging failed:", error);
  }
}

async function signedInvalid(env, message, status, nonce) {
  return signedResponse(env, { success: false, valid: false, error: message }, status, nonce);
}

async function signedError(env, message, status, nonce) {
  return signedResponse(env, { success: false, error: message }, status, nonce);
}

async function signedResponse(env, data, status = 200, nonce = "") {
  const payloadObject = {
    protocol: PROTOCOL,
    request_id: crypto.randomUUID(),
    server_time: Math.floor(Date.now() / 1000),
    nonce: nonce || "",
    data,
  };
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payloadObject));
  const privateKey = await importSigningPrivateKey(env);
  const signature = await crypto.subtle.sign("Ed25519", privateKey, payloadBytes);

  return json({
    key_id: SIGNING_KEY_ID,
    algorithm: "Ed25519",
    payload: bytesToBase64Url(payloadBytes),
    signature: bytesToBase64Url(new Uint8Array(signature)),
  }, status);
}

async function importSigningPrivateKey(env) {
  let jwk;
  try {
    jwk = JSON.parse(env.ELITEAUTH_SIGNING_PRIVATE_JWK);
  } catch {
    throw new Error("ELITEAUTH_SIGNING_PRIVATE_JWK is not valid JSON");
  }
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.d || jwk.x !== SIGNING_PUBLIC_KEY) {
    throw new Error("The configured signing key does not match the pinned EliteAuth public key");
  }
  return crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]);
}

async function selectOne(env, table, parameters) {
  const rows = await selectRows(env, table, { ...parameters, limit: "1" });
  return rows[0] || null;
}

async function selectRows(env, table, parameters = {}) {
  const response = await fetch(buildSupabaseUrl(env, table, parameters), {
    method: "GET",
    headers: supabaseHeaders(env),
  });
  if (!response.ok) {
    const text = await response.text();
    console.error("Supabase SELECT error:", response.status, text);
    throw new Error(`Supabase SELECT failed with ${response.status}`);
  }
  return response.json();
}

async function insertRow(env, table, data) {
  const response = await fetch(buildSupabaseUrl(env, table), {
    method: "POST",
    headers: { ...supabaseHeaders(env), Prefer: "return=minimal" },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const text = await response.text();
    console.error("Supabase INSERT error:", response.status, text);
    throw new Error(`Supabase INSERT failed with ${response.status}`);
  }
}

async function updateRowsReturning(env, table, filters, data) {
  const response = await fetch(buildSupabaseUrl(env, table, filters), {
    method: "PATCH",
    headers: { ...supabaseHeaders(env), Prefer: "return=representation" },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const text = await response.text();
    console.error("Supabase PATCH error:", response.status, text);
    throw new Error(`Supabase PATCH failed with ${response.status}`);
  }
  return response.json();
}

function buildSupabaseUrl(env, table, parameters = {}) {
  const url = new URL(`${trimSlash(env.SUPABASE_URL)}/rest/v1/${table}`);
  for (const [name, value] of Object.entries(parameters)) {
    if (value !== undefined && value !== null && value !== "") url.searchParams.set(name, String(value));
  }
  return url.toString();
}

function supabaseHeaders(env) {
  return {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    "content-type": "application/json",
  };
}

async function readJsonBody(request) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return { ok: false, error: "Content-Type must be application/json" };
  }
  try {
    const data = await request.json();
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return { ok: false, error: "Request body must be a JSON object" };
    }
    return { ok: true, data };
  } catch {
    return { ok: false, error: "Invalid JSON request body" };
  }
}

function validateEnvironment(env) {
  if (!env.SUPABASE_URL) throw new Error("SUPABASE_URL is not configured");
  if (!env.SUPABASE_SERVICE_ROLE_KEY) throw new Error("SUPABASE_SERVICE_ROLE_KEY is not configured");
  if (!env.ELITEAUTH_SIGNING_PRIVATE_JWK) throw new Error("ELITEAUTH_SIGNING_PRIVATE_JWK is not configured");
}

function normalizePath(pathname) {
  return pathname === "/" ? "/" : pathname.replace(/\/+$/, "");
}

function normalizeSha256(value) {
  const cleaned = cleanString(value).toLowerCase();
  return /^[a-f0-9]{64}$/.test(cleaned) ? cleaned : "";
}

function cleanString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function isExpired(value) {
  if (!value) return false;
  const timestamp = new Date(value).getTime();
  return !Number.isFinite(timestamp) || timestamp <= Date.now();
}

function timingSafeHexEqual(left, right) {
  if (!/^[a-f0-9]{64}$/i.test(left) || !/^[a-f0-9]{64}$/i.test(right)) return false;
  const a = hexToBytes(left);
  const b = hexToBytes(right);
  return crypto.subtle.timingSafeEqual(a, b);
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function randomBase64Url(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function trimSlash(value) {
  return String(value).replace(/\/+$/, "");
}

function corsHeaders() {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "Content-Type, Authorization",
    "access-control-max-age": "86400",
  };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...corsHeaders(), ...extraHeaders },
  });
}

function methodNotAllowed(env, allow) {
  return signedError(env, "Method not allowed", 405, "").then(response => {
    const headers = new Headers(response.headers);
    headers.set("Allow", allow);
    return new Response(response.body, { status: 405, headers });
  });
}
