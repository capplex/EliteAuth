from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ELITEAUTH_SIGNING_PUBLIC_KEY = "Yo7wBxsz8mCN6LX89Ja0H3pNlcLXJHrJ50u5BtZuakQ"
ELITEAUTH_SIGNING_KEY_ID = "eliteauth-ed25519-2026-01"


@dataclass(slots=True)
class EliteAuthResult:
    success: bool
    data: dict[str, Any]
    http_status: int
    request_id: str

    @property
    def error(self) -> str | None:
        value = self.data.get("error")
        return str(value) if value is not None else None

    @property
    def valid(self) -> bool:
        return bool(self.data.get("valid", False))


class EliteAuthClient:
    def __init__(
        self,
        api_url: str,
        app_id: str,
        version: str,
        *,
        integrity_sha256: str = "",
        public_key: str = ELITEAUTH_SIGNING_PUBLIC_KEY,
        sdk_version: str = "python-1.1.0",
        max_server_skew_seconds: int = 300,
        timeout_seconds: int = 15,
    ) -> None:
        if not api_url or not app_id or not version:
            raise ValueError("api_url, app_id and version are required")
        self.api_url = api_url.rstrip("/")
        self.app_id = app_id
        self.version = version
        self.integrity_sha256 = _normalize_hash(integrity_sha256)
        self.sdk_version = sdk_version
        self.max_server_skew_seconds = max_server_skew_seconds
        self.timeout_seconds = timeout_seconds
        self._public_key = Ed25519PublicKey.from_public_bytes(_b64url_decode(public_key))
        self._session_token: str | None = None
        self._challenge: str | None = None

    def activate(self, license_key: str, hwid: str) -> EliteAuthResult:
        nonce = _random_b64url(24)
        result = self._post_signed(
            "/v1/license/activate",
            {
                "app_id": self.app_id,
                "license_key": license_key,
                "hwid": hwid,
                "version": self.version,
                "sdk_version": self.sdk_version,
                "integrity_sha256": self.integrity_sha256 or None,
                "timestamp": int(time.time()),
                "nonce": nonce,
            },
            nonce,
        )
        if result.success:
            session = result.data.get("session") or {}
            self._session_token = session.get("token")
            self._challenge = session.get("challenge")
            if not self._session_token or not self._challenge:
                raise RuntimeError("Signed activation response is missing session state")
        return result

    def check_session(self, hwid: str) -> EliteAuthResult:
        if not self._session_token or not self._challenge:
            raise RuntimeError("Call activate() before check_session()")
        nonce = _random_b64url(24)
        result = self._post_signed(
            "/v1/session/check",
            {
                "app_id": self.app_id,
                "session_token": self._session_token,
                "challenge": self._challenge,
                "hwid": hwid,
                "sdk_version": self.sdk_version,
                "integrity_sha256": self.integrity_sha256 or None,
                "timestamp": int(time.time()),
                "nonce": nonce,
            },
            nonce,
        )
        if result.success and result.valid:
            next_challenge = (result.data.get("session") or {}).get("challenge")
            if not next_challenge:
                raise RuntimeError("Signed session response did not rotate the challenge")
            self._challenge = next_challenge
        return result

    def clear_session(self) -> None:
        self._session_token = None
        self._challenge = None

    def _post_signed(self, path: str, body: dict[str, Any], expected_nonce: str) -> EliteAuthResult:
        raw_request = json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=raw_request,
            method="POST",
            headers={"Content-Type": "application/json", "Cache-Control": "no-store"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                status = response.status
                raw_response = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            raw_response = exc.read()
        envelope = json.loads(raw_response.decode("utf-8"))
        payload = self._verify_envelope(envelope, expected_nonce)
        data = payload.get("data")
        if not isinstance(data, dict):
            raise RuntimeError("Signed EliteAuth payload is missing data")
        return EliteAuthResult(bool(data.get("success")), data, status, str(payload.get("request_id", "")))

    def _verify_envelope(self, envelope: dict[str, Any], expected_nonce: str) -> dict[str, Any]:
        if envelope.get("key_id") != ELITEAUTH_SIGNING_KEY_ID or envelope.get("algorithm") != "Ed25519":
            raise RuntimeError("Unexpected EliteAuth signing key or algorithm")
        payload_bytes = _b64url_decode(str(envelope.get("payload", "")))
        signature = _b64url_decode(str(envelope.get("signature", "")))
        self._public_key.verify(signature, payload_bytes)
        payload = json.loads(payload_bytes.decode("utf-8"))
        if payload.get("protocol") != "eliteauth-signed-v1":
            raise RuntimeError("Unsupported EliteAuth signed-response protocol")
        if payload.get("nonce") != expected_nonce:
            raise RuntimeError("EliteAuth response nonce mismatch")
        server_time = payload.get("server_time")
        if not isinstance(server_time, int) or abs(int(time.time()) - server_time) > self.max_server_skew_seconds:
            raise RuntimeError("EliteAuth response timestamp is outside the allowed window")
        return payload


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_hash(value: str) -> str:
    result = value.strip().lower()
    if result and (len(result) != 64 or any(char not in "0123456789abcdef" for char in result)):
        raise ValueError("integrity_sha256 must be a 64-character SHA-256 value")
    return result


def _random_b64url(length: int) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(length)).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
