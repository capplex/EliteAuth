# EliteAuth signed SDKs

All clients implement the same protocol:

1. Add `timestamp`, a random `nonce`, SDK version, and optional release SHA-256 to each request.
2. Verify the Ed25519 signature over the exact returned payload bytes.
3. Confirm the response nonce matches the request and the server timestamp is fresh.
4. Store the activation session token and one-time challenge only after verification.
5. Send the challenge during session checks and replace it with the newly signed challenge.

Dependencies:

- JavaScript/TypeScript: modern WebCrypto runtime with Ed25519 support
- Python: `cryptography`
- Go: standard library only
- Java: Java 17 + Jackson
- C#: .NET 8 + NSec.Cryptography
- C++: C++20 + libcurl + libsodium + nlohmann/json
- Rust: dependencies listed in `Cargo.toml`

The public signing key is intentionally client-safe and pinned in source. The private signing JWK must remain only in the Cloudflare Worker secret store.
