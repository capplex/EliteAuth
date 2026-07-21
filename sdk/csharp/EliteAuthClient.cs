using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NSec.Cryptography;

namespace EliteAuth;

public sealed class EliteAuthClient : IDisposable
{
    public const string SigningPublicKey = "Yo7wBxsz8mCN6LX89Ja0H3pNlcLXJHrJ50u5BtZuakQ";
    public const string SigningKeyId = "eliteauth-ed25519-2026-01";

    private readonly HttpClient _http;
    private readonly string _apiUrl;
    private readonly string _appId;
    private readonly string _version;
    private readonly string? _integritySha256;
    private readonly PublicKey _verificationKey;
    private string? _sessionToken;
    private string? _challenge;

    public EliteAuthClient(string apiUrl, string appId, string version, string? integritySha256 = null, HttpClient? httpClient = null)
    {
        if (string.IsNullOrWhiteSpace(apiUrl) || string.IsNullOrWhiteSpace(appId) || string.IsNullOrWhiteSpace(version))
            throw new ArgumentException("apiUrl, appId and version are required");

        _apiUrl = apiUrl.TrimEnd('/');
        _appId = appId;
        _version = version;
        _integritySha256 = NormalizeHash(integritySha256);
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        _verificationKey = PublicKey.Import(SignatureAlgorithm.Ed25519, Base64UrlDecode(SigningPublicKey), KeyBlobFormat.RawPublicKey);
    }

    public async Task<EliteAuthResult> ActivateAsync(string licenseKey, string hwid, CancellationToken cancellationToken = default)
    {
        var nonce = RandomBase64Url(24);
        var result = await PostSignedAsync("/v1/license/activate", new
        {
            app_id = _appId,
            license_key = licenseKey,
            hwid,
            version = _version,
            sdk_version = "csharp-1.1.0",
            integrity_sha256 = _integritySha256,
            timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            nonce
        }, nonce, cancellationToken);

        if (result.Success)
        {
            var session = result.Data.GetProperty("session");
            _sessionToken = session.GetProperty("token").GetString();
            _challenge = session.GetProperty("challenge").GetString();
            if (string.IsNullOrEmpty(_sessionToken) || string.IsNullOrEmpty(_challenge))
                throw new CryptographicException("Signed activation response is missing session state");
        }
        return result;
    }

    public async Task<EliteAuthResult> CheckSessionAsync(string hwid, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(_sessionToken) || string.IsNullOrEmpty(_challenge))
            throw new InvalidOperationException("Call ActivateAsync before CheckSessionAsync");

        var nonce = RandomBase64Url(24);
        var result = await PostSignedAsync("/v1/session/check", new
        {
            app_id = _appId,
            session_token = _sessionToken,
            challenge = _challenge,
            hwid,
            sdk_version = "csharp-1.1.0",
            integrity_sha256 = _integritySha256,
            timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            nonce
        }, nonce, cancellationToken);

        if (result.Success && result.Valid)
        {
            var next = result.Data.GetProperty("session").GetProperty("challenge").GetString();
            if (string.IsNullOrEmpty(next)) throw new CryptographicException("Signed session response did not rotate the challenge");
            _challenge = next;
        }
        return result;
    }

    public void ClearSession()
    {
        _sessionToken = null;
        _challenge = null;
    }

    private async Task<EliteAuthResult> PostSignedAsync(string path, object body, string expectedNonce, CancellationToken cancellationToken)
    {
        using var response = await _http.PostAsJsonAsync(_apiUrl + path, body, cancellationToken);
        var raw = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        using var envelopeDocument = JsonDocument.Parse(raw);
        var envelope = envelopeDocument.RootElement;

        if (envelope.GetProperty("key_id").GetString() != SigningKeyId || envelope.GetProperty("algorithm").GetString() != "Ed25519")
            throw new CryptographicException("Unexpected EliteAuth signing key or algorithm");

        var payloadBytes = Base64UrlDecode(envelope.GetProperty("payload").GetString() ?? "");
        var signatureBytes = Base64UrlDecode(envelope.GetProperty("signature").GetString() ?? "");
        if (!SignatureAlgorithm.Ed25519.Verify(_verificationKey, payloadBytes, signatureBytes))
            throw new CryptographicException("EliteAuth response signature verification failed");

        using var payloadDocument = JsonDocument.Parse(payloadBytes);
        var payload = payloadDocument.RootElement;
        if (payload.GetProperty("protocol").GetString() != "eliteauth-signed-v1")
            throw new CryptographicException("Unsupported EliteAuth signed-response protocol");
        if (payload.GetProperty("nonce").GetString() != expectedNonce)
            throw new CryptographicException("EliteAuth response nonce mismatch");

        var serverTime = payload.GetProperty("server_time").GetInt64();
        if (Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - serverTime) > 300)
            throw new CryptographicException("EliteAuth response timestamp is outside the allowed window");

        var data = payload.GetProperty("data").Clone();
        return new EliteAuthResult(
            data.GetProperty("success").GetBoolean(),
            data.TryGetProperty("valid", out var valid) && valid.GetBoolean(),
            data.TryGetProperty("error", out var error) ? error.GetString() : null,
            data,
            (int)response.StatusCode,
            payload.GetProperty("request_id").GetString() ?? ""
        );
    }

    public static async Task<string> Sha256FileAsync(string path, CancellationToken cancellationToken = default)
    {
        await using var stream = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string? NormalizeHash(string? value)
    {
        var hash = value?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(hash)) return null;
        if (hash.Length != 64 || hash.Any(c => !Uri.IsHexDigit(c))) throw new ArgumentException("integritySha256 must be a 64-character SHA-256 value");
        return hash;
    }

    private static string RandomBase64Url(int byteLength) => Base64UrlEncode(RandomNumberGenerator.GetBytes(byteLength));
    private static string Base64UrlEncode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Base64UrlDecode(string value)
    {
        var text = value.Replace('-', '+').Replace('_', '/');
        text += new string('=', (4 - text.Length % 4) % 4);
        return Convert.FromBase64String(text);
    }

    public void Dispose()
    {
        _verificationKey.Dispose();
        _http.Dispose();
    }
}

public sealed record EliteAuthResult(bool Success, bool Valid, string? Error, JsonElement Data, int HttpStatus, string RequestId);
