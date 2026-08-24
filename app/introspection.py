"""RFC 7662 access-token introspection."""
from __future__ import annotations

import base64
from typing import Any

import httpx

from .config import get_settings
from .discovery import DiscoveryError, discover

class IntrospectionError(ValueError):
    def __init__(self, category: str, message: str | None = None):
        super().__init__(message or category)
        self.category = category


def _safe_claims(data: dict[str, Any], issuer: str) -> dict[str, Any]:
    if data.get('active') is not True:
        raise IntrospectionError('introspection_inactive')
    response_issuer = data.get('iss')
    if response_issuer is not None and response_issuer.rstrip('/') != issuer.rstrip('/'):
        raise IntrospectionError('introspection_issuer_mismatch')
    if not isinstance(data.get('sub'), str) or not data['sub']:
        raise IntrospectionError('introspection_missing_subject')
    claims: dict[str, Any] = {
        'iss': issuer,
        'sub': data['sub'],
    }
    for name in ('aud', 'scope', 'client_id', 'token_type', 'exp', 'iat', 'nbf', 'act'):
        if name in data:
            claims[name] = data[name]
    return claims


def introspect(token: str, *, issuer: str) -> dict[str, Any]:
    """Introspect one token at its issuer's RFC 7662 endpoint."""
    settings = get_settings()
    try:
        metadata = discover(issuer)
        endpoint = metadata.get('introspection_endpoint')
        if not isinstance(endpoint, str) or not endpoint:
            raise IntrospectionError('introspection_endpoint_missing')
        basic = base64.b64encode(
            f'{settings.introspection_client_id}:{settings.introspection_client_secret}'.encode()
        ).decode()
        response = httpx.post(
            endpoint,
            data={
                'token': token,
                'token_type_hint': 'access_token',
            },
            headers={
                'Authorization': f'Basic {basic}',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            timeout=settings.introspection_timeout_seconds,
        )
    except (httpx.HTTPError, DiscoveryError) as exc:
        raise IntrospectionError('introspection_unavailable') from exc
    if response.status_code >= 500 or response.status_code == 429:
        raise IntrospectionError('introspection_unavailable')
    if response.status_code >= 400:
        raise IntrospectionError('introspection_invalid')
    try:
        data = response.json()
    except ValueError as exc:
        raise IntrospectionError('introspection_invalid') from exc
    if not isinstance(data, dict):
        raise IntrospectionError('introspection_invalid')
    return _safe_claims(data, issuer)


