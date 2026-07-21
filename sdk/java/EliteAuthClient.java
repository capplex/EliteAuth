import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class EliteAuthClient {
    public static final String SIGNING_PUBLIC_KEY = "Yo7wBxsz8mCN6LX89Ja0H3pNlcLXJHrJ50u5BtZuakQ";
    public static final String SIGNING_KEY_ID = "eliteauth-ed25519-2026-01";

    private final String apiUrl;
    private final String appId;
    private final String version;
    private final String integritySha256;
    private final String sdkVersion;
    private final long maxServerSkewSeconds;
    private final HttpClient httpClient;
    private final ObjectMapper json = new ObjectMapper();
    private final PublicKey verificationKey;
    private String sessionToken;
    private String challenge;

    public EliteAuthClient(String apiUrl, String appId, String version, String integritySha256) {
        try {
            this.apiUrl = require(apiUrl, "apiUrl").replaceAll("/+$", "");
            this.appId = require(appId, "appId");
            this.version = require(version, "version");
            this.integritySha256 = normalizeHash(integritySha256);
            this.sdkVersion = "java-1.1.0";
            this.maxServerSkewSeconds = 300;
            this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
            this.verificationKey = importEd25519PublicKey(SIGNING_PUBLIC_KEY);
        } catch (Exception error) {
            throw new IllegalArgumentException("Unable to initialize EliteAuth SDK", error);
        }
    }

    public Result activate(String licenseKey, String hwid) throws Exception {
        String nonce = randomNonce();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("app_id", appId);
        body.put("license_key", licenseKey);
        body.put("hwid", hwid);
        body.put("version", version);
        body.put("sdk_version", sdkVersion);
        body.put("integrity_sha256", integritySha256.isEmpty() ? null : integritySha256);
        body.put("timestamp", Instant.now().getEpochSecond());
        body.put("nonce", nonce);
        Result result = postSigned("/v1/license/activate", body, nonce);
        if (result.success()) {
            JsonNode session = result.data().path("session");
            sessionToken = text(session, "token");
            challenge = text(session, "challenge");
            if (sessionToken == null || challenge == null) throw new SecurityException("Signed activation response is missing session state");
        }
        return result;
    }

    public Result checkSession(String hwid) throws Exception {
        if (sessionToken == null || challenge == null) throw new IllegalStateException("Call activate before checkSession");
        String nonce = randomNonce();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("app_id", appId);
        body.put("session_token", sessionToken);
        body.put("challenge", challenge);
        body.put("hwid", hwid);
        body.put("sdk_version", sdkVersion);
        body.put("integrity_sha256", integritySha256.isEmpty() ? null : integritySha256);
        body.put("timestamp", Instant.now().getEpochSecond());
        body.put("nonce", nonce);
        Result result = postSigned("/v1/session/check", body, nonce);
        if (result.success() && result.valid()) {
            String next = text(result.data().path("session"), "challenge");
            if (next == null) throw new SecurityException("Signed session response did not rotate the challenge");
            challenge = next;
        }
        return result;
    }

    public void clearSession() {
        sessionToken = null;
        challenge = null;
    }

    private Result postSigned(String path, Map<String, Object> body, String expectedNonce) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(apiUrl + path))
                .timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/json")
                .header("Cache-Control", "no-store")
                .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        JsonNode envelope = json.readTree(response.body());
        JsonNode payload = verifyEnvelope(envelope, expectedNonce);
        JsonNode data = payload.path("data");
        if (!data.isObject()) throw new SecurityException("Signed EliteAuth payload is missing data");
        return new Result(data.path("success").asBoolean(false), data.path("valid").asBoolean(false), data.path("error").isTextual() ? data.path("error").asText() : null, data, response.statusCode(), payload.path("request_id").asText());
    }

    private JsonNode verifyEnvelope(JsonNode envelope, String expectedNonce) throws Exception {
        if (!SIGNING_KEY_ID.equals(envelope.path("key_id").asText()) || !"Ed25519".equals(envelope.path("algorithm").asText())) {
            throw new SecurityException("Unexpected EliteAuth signing key or algorithm");
        }
        byte[] payloadBytes = decodeBase64Url(envelope.path("payload").asText());
        byte[] signatureBytes = decodeBase64Url(envelope.path("signature").asText());
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(verificationKey);
        verifier.update(payloadBytes);
        if (!verifier.verify(signatureBytes)) throw new SecurityException("EliteAuth response signature verification failed");
        JsonNode payload = json.readTree(payloadBytes);
        if (!"eliteauth-signed-v1".equals(payload.path("protocol").asText())) throw new SecurityException("Unsupported EliteAuth protocol");
        if (!Objects.equals(expectedNonce, payload.path("nonce").asText())) throw new SecurityException("EliteAuth response nonce mismatch");
        long serverTime = payload.path("server_time").asLong(Long.MIN_VALUE);
        if (serverTime == Long.MIN_VALUE || Math.abs(Instant.now().getEpochSecond() - serverTime) > maxServerSkewSeconds) {
            throw new SecurityException("EliteAuth response timestamp is outside the allowed window");
        }
        return payload;
    }

    public static String sha256File(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[1024 * 1024];
            for (int read; (read = input.read(buffer)) >= 0; ) digest.update(buffer, 0, read);
        }
        return hex(digest.digest());
    }

    private static PublicKey importEd25519PublicKey(String rawBase64Url) throws Exception {
        byte[] raw = decodeBase64Url(rawBase64Url);
        byte[] prefix = hexBytes("302a300506032b6570032100");
        byte[] encoded = new byte[prefix.length + raw.length];
        System.arraycopy(prefix, 0, encoded, 0, prefix.length);
        System.arraycopy(raw, 0, encoded, prefix.length, raw.length);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static String randomNonce() {
        byte[] bytes = new byte[24];
        new java.security.SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String normalizeHash(String value) {
        String hash = value == null ? "" : value.trim().toLowerCase();
        if (!hash.isEmpty() && !hash.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("integritySha256 must be a 64-character SHA-256 value");
        return hash;
    }

    private static String require(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
        return value;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isTextual() && !value.asText().isBlank() ? value.asText() : null;
    }

    private static byte[] decodeBase64Url(String value) { return Base64.getUrlDecoder().decode(value); }
    private static byte[] hexBytes(String value) { byte[] out = new byte[value.length() / 2]; for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16); return out; }
    private static String hex(byte[] value) { StringBuilder out = new StringBuilder(value.length * 2); for (byte b : value) out.append(String.format("%02x", b)); return out.toString(); }

    public record Result(boolean success, boolean valid, String error, JsonNode data, int httpStatus, String requestId) {}
}
