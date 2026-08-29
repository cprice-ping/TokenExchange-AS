"""PingOne Authorize decision client for token-exchange policy."""
from __future__ import annotations

import base64
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .config import get_settings

class P1AZError(RuntimeError):
    def __init__(self, category: str, message: str = "PingOne Authorize unavailable"):
        super().__init__(message)
        self.category = category

@dataclass
class _WorkerToken:
    value: str
    expires_at: float

class PingOneAuthorize:
    def __init__(self):
        self._cached: _WorkerToken | None = None
        self._lock = threading.Lock()

    def configured(self) -> bool:
        s = get_settings()
        return bool(s.p1az_environment_id and s.p1az_decision_endpoint_id and s.p1az_worker_client_id and s.p1az_worker_client_secret)

    def _worker_token(self, *, force=False) -> str:
        s = get_settings()
        now = time.time()
        with self._lock:
            if not force and self._cached and self._cached.expires_at > now + s.p1az_token_safety_seconds:
                return self._cached.value
            url = f"{s.p1az_auth_base.rstrip('/')}/{s.p1az_environment_id}/as/token"
            basic = base64.b64encode(f"{s.p1az_worker_client_id}:{s.p1az_worker_client_secret}".encode()).decode()
            try:
                response = httpx.post(url, data={"grant_type": "client_credentials"}, headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"}, timeout=s.p1az_timeout_seconds)
            except httpx.HTTPError as exc:
                raise P1AZError("worker_network") from exc
            if response.status_code >= 400:
                raise P1AZError("worker_auth")
            try:
                body = response.json(); token = body["access_token"]; expires = int(body.get("expires_in", 300))
            except (ValueError, KeyError, TypeError) as exc:
                raise P1AZError("worker_response") from exc
            if not isinstance(token, str) or not token or expires <= 0:
                raise P1AZError("worker_response")
            self._cached = _WorkerToken(token, now + expires)
            return token

    def decide(self, *, subject: dict[str, Any], actor: dict[str, Any] | None, subject_token_type: str, actor_token_type: str | None, requested_audience: str | None = None, requested_scope: str | None = None, client_id: str | None = None) -> dict[str, Any]:
        s = get_settings()
        if not self.configured():
            raise P1AZError("not_configured")
        parameters = {
            "Request.TokenExchange.Subject.sub": str(subject["sub"]),
            "Request.TokenExchange.Subject.iss": str(subject["iss"]),
            # These are the RFC 8693 request values. They are deliberately
            # separate from claims on either incoming JWT: P1AZ decides
            # whether the requested output scope/audience is allowed.
            "Request.TokenExchange.scope": str(requested_scope or ""),
            "Request.TokenExchange.aud": str(requested_audience or ""),
        }
        if actor is not None:
            parameters.update({
                "Request.TokenExchange.Actor.sub": str(actor["sub"]),
                "Request.TokenExchange.Actor.iss": str(actor["iss"]),
            })
        token = self._worker_token()
        url = f"{s.p1az_api_base.rstrip('/')}/environments/{s.p1az_environment_id}/decisionEndpoints/{s.p1az_decision_endpoint_id}"
        response = self._post_decision(url, parameters, token)
        if response.status_code == 401:
            token = self._worker_token(force=True)
            response = self._post_decision(url, parameters, token)
        if response.status_code >= 400:
            raise P1AZError("decision_rejected" if response.status_code < 500 else "decision_unavailable")
        try:
            result = response.json()
        except ValueError as exc:
            raise P1AZError("decision_response") from exc
        decision = str(result.get("decision", "")).upper()
        if decision == "PERMIT": return result
        if decision == "DENY": raise P1AZError("denied", "token exchange denied")
        raise P1AZError("decision_unavailable")

    def _post_decision(self, url: str, parameters: dict[str, str], token: str) -> httpx.Response:
        """POST the decision request with a bounded 429 retry.

        Retries honor Retry-After (seconds or HTTP-date) when present, falling
        back to a capped exponential backoff. Unbounded retries are not
        possible: P1AZ throttling must surface to the caller instead of
        stalling token exchanges.
        """
        s = get_settings()
        max_attempts = 3
        backoff_seconds = 0.25
        response: httpx.Response | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                response = httpx.post(url, json={"parameters": parameters}, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, timeout=s.p1az_timeout_seconds)
            except httpx.HTTPError as exc:
                raise P1AZError("decision_network") from exc
            if response.status_code != 429 or attempt == max_attempts:
                return response
            retry_after = self._retry_after_seconds(response.headers.get("Retry-After"))
            delay = retry_after if retry_after is not None else backoff_seconds * (2 ** (attempt - 1))
            time.sleep(min(delay, 2.0))
        return response  # pragma: no cover - loop always returns or raises

    @staticmethod
    def _retry_after_seconds(value: str | None) -> float | None:
        if not value:
            return None
        try:
            seconds = float(value)
            return max(0.0, seconds)
        except ValueError:
            pass
        try:
            from email.utils import parsedate_to_datetime
            delay = (parsedate_to_datetime(value).timestamp() - time.time())
            return max(0.0, delay)
        except (TypeError, ValueError):
            return None

def _claim_string(value: Any) -> str:
    if value is None: return ""
    if isinstance(value, list): return " ".join(sorted(str(item) for item in value))
    return str(value)

p1az = PingOneAuthorize()
