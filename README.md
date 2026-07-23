<div align="center">

<img src="website/assets/eliteauth-logo.png" alt="EliteAuth logo" width="150">

# EliteAuth

### Free and open-source authentication and licensing for developers

Manage applications, licenses, users, devices, sessions, HWID binding, expiry, and access control from one modern platform.

[![Website](https://img.shields.io/badge/Hosted-eliteauth.lol-8A2BE2?style=for-the-badge)](https://eliteauth.lol)
[![License](https://img.shields.io/badge/License-Apache%202.0-2563EB?style=for-the-badge)](LICENSE)
[![Open Source](https://img.shields.io/badge/Open%20Source-Yes-16A34A?style=for-the-badge)](https://github.com/capplex/EliteAuth)

**Hosted for free • Self-hostable • Unlimited usage • Multi-language SDKs**

</div>

---

## Overview

EliteAuth is an open-source authentication and software-licensing platform. Use the hosted service at [eliteauth.lol](https://eliteauth.lol), or deploy the website, database schema, and API worker on your own infrastructure.

## Features

- Unlimited applications, licenses, users, and sessions
- License creation, revocation, expiry, and version checks
- HWID binding and reset workflows
- Signed API responses and replay protection
- Session validation, rotation, and revocation
- Build SHA-256 allowlisting
- Audit and security-event records
- REST API and SDKs for C#, C++, JavaScript, TypeScript, Python, Java, Go, and Rust
- Responsive developer dashboard
- Docker-based local website preview

## Repository layout

```text
EliteAuth/
├── website/                 Static frontend and dashboard
├── worker/                  Cloudflare Worker REST API
├── supabase/migrations/     Database schema and security migrations
├── sdk/                     Official multi-language clients
├── scripts/                 Signing-key utilities
├── docs/                    Architecture, API, deployment, and SDK guides
├── deploy/                  Local Nginx configuration
├── .github/                 CI and issue templates
├── docker-compose.yml
├── Dockerfile
└── README.md
```

## Quick start

### Hosted

Create an account at [eliteauth.lol](https://eliteauth.lol).

### Local website preview

1. Edit `website/supabase-config.js` with your public Supabase URL and publishable key.
2. Start the website:

```bash
git clone https://github.com/capplex/EliteAuth.git
cd EliteAuth
docker compose up -d
```

Open [http://localhost:3000](http://localhost:3000).

For a complete self-hosted deployment, follow [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). The API requires Supabase and a Cloudflare Worker-compatible runtime.

## Security

Never commit a Supabase service-role key, signing private JWK, application server secret, or active session token. Store backend credentials as encrypted Worker secrets.

EliteAuth provides authentication, licensing, HWID binding, signed responses, session checks, and access control. Client-side licensing is not a complete anti-reversing solution; distributed applications should still use appropriate obfuscation and integrity checks.

Report vulnerabilities privately to [security@eliteauth.lol](mailto:security@eliteauth.lol). See [SECURITY.md](SECURITY.md).

## Contact

- Support: [support@eliteauth.lol](mailto:support@eliteauth.lol)
- Administration: [admin@eliteauth.lol](mailto:admin@eliteauth.lol)
- Security: [security@eliteauth.lol](mailto:security@eliteauth.lol)
- Website: [eliteauth.lol](https://eliteauth.lol) [eliteauth.cc](https://eliteauth.cc)
- Discord: `eliteauth`

## Contributing

Issues and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes.

## License

Licensed under the [Apache License 2.0](LICENSE).
