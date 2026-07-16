"""HTTP client for the Zablo admin & secrets API."""

from __future__ import annotations

import sys
from typing import Any, Optional

import httpx


class ApiError(RuntimeError):
    def __init__(self, status: int, message: str, body: Any = None):
        super().__init__(f"{status}: {message}")
        self.status = status
        self.body = body


class Client:
    def __init__(self, api_url: str, api_key: Optional[str] = None, timeout: float = 30.0):
        self._url = api_url.rstrip("/")
        self._key = api_key
        self._http = httpx.Client(
            base_url=self._url,
            timeout=timeout,
            headers=self._default_headers(),
        )

    def _default_headers(self) -> dict[str, str]:
        h = {
            "user-agent": "zablo-cli/0.1.0 (python)",
            "accept": "application/json",
        }
        if self._key:
            h["authorization"] = f"Bearer {self._key}"
        return h

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ---- core helpers ----

    def _call(self, method: str, path: str, body: Optional[dict[str, Any]] = None) -> Any:
        try:
            r = self._http.request(method, path, json=body)
        except httpx.RequestError as e:
            sys.exit(f"zablo: network error reaching {self._url}: {e}")
        if r.status_code == 204:
            return None
        try:
            data = r.json() if r.content else None
        except ValueError:
            data = r.text
        if r.is_error:
            msg = (
                data.get("error", str(data)) if isinstance(data, dict) else str(data) or r.reason_phrase
            )
            raise ApiError(r.status_code, msg, data)
        return data

    # ---- secrets ----

    def put_secret(
        self,
        path: str,
        ciphertext_b64: str,
        client_iv_b64: str,
        client_salt_b64: str,
        kind: str = "standard",
        envelope_version: int = 1,
    ) -> dict[str, Any]:
        return self._call(
            "POST",
            "/v1/secrets",
            {
                "path": path,
                "ciphertext": ciphertext_b64,
                "clientIv": client_iv_b64,
                "clientSalt": client_salt_b64,
                "algorithm": "AES-256-GCM",
                "envelopeVersion": envelope_version,
                "kind": kind,
            },
        )

    def get_secret(self, path: str) -> dict[str, Any]:
        return self._call("GET", f"/v1/secrets/{path.lstrip('/')}")

    def list_secrets(self, prefix: Optional[str] = None) -> list[dict[str, Any]]:
        q = f"?prefix={prefix}" if prefix else ""
        data = self._call("GET", f"/v1/secrets{q}")
        return data.get("secrets", []) if isinstance(data, dict) else []

    def delete_secret(self, path: str) -> None:
        self._call("DELETE", f"/v1/secrets/{path.lstrip('/')}")

    # ---- federation ----

    def federate(self, subject_token: str, audience: str = "zablo.io") -> dict[str, Any]:
        return self._call(
            "POST",
            "/v1/auth/federate",
            {
                "subject_token": subject_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "audience": audience,
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            },
        )
