# REST API

The Worker source in `worker/worker.js` is the canonical implementation.

Common routes include:

- `GET /health` — service health
- `GET /v1/keys` — public response-verification key metadata
- `POST /v1/license/activate` — activate and bind a license
- `POST /v1/session/check` — validate an active session

Send JSON requests over HTTPS. Applications should validate signed responses, timestamps, nonces, and session challenges as demonstrated in the SDKs.
