"""Safe OIDC discovery and JWKS retrieval for administrator-configured issuers."""
from __future__ import annotations
import ipaddress, socket
from urllib.parse import urlparse
import httpx

MAX_RESPONSE_BYTES = 1_000_000

class DiscoveryError(ValueError): pass

def normalize_issuer(value: str) -> str:
    value = value.strip().rstrip('/')
    parsed = urlparse(value)
    if parsed.scheme not in ('https', 'http') or parsed.username or parsed.password or parsed.fragment or not parsed.netloc:
        raise ValueError('issuer must be an absolute HTTPS URL without credentials or fragments')
    from .config import get_settings
    if parsed.scheme != 'https' and not get_settings().allow_insecure_http:
        raise ValueError('issuer must use HTTPS')
    if parsed.query:
        raise ValueError('issuer must not contain a query string')
    _assert_safe_host(parsed.hostname or '')
    return value

def _assert_safe_host(host: str) -> None:
    if host.lower() in {'localhost', 'metadata.google.internal'}:
        raise DiscoveryError('issuer host is not permitted')
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise DiscoveryError('issuer host could not be resolved') from exc
    for address in addresses:
        if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or address.is_unspecified:
            raise DiscoveryError('issuer host resolves to a private or reserved address')

def _get_json(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        from .config import get_settings
        if not get_settings().allow_insecure_http:
            raise DiscoveryError('discovery endpoints must use HTTPS')
    _assert_safe_host(parsed.hostname or '')
    try:
        with httpx.Client(timeout=httpx.Timeout(5.0, connect=3.0), follow_redirects=False) as client:
            response = client.get(url, headers={'Accept': 'application/json'})
    except httpx.HTTPError as exc:
        raise DiscoveryError('issuer metadata unavailable') from exc
    # httpx exposes redirect status codes consistently across supported
    # versions; avoid relying on ``is_permanent_redirect``, which is not
    # available on every Response implementation.
    if response.status_code in {301, 302, 303, 307, 308}:
        raise DiscoveryError('discovery redirects are not permitted')
    if response.status_code != 200 or len(response.content) > MAX_RESPONSE_BYTES:
        raise DiscoveryError('issuer metadata unavailable')
    try: return response.json()
    except ValueError as exc: raise DiscoveryError('issuer metadata is not JSON') from exc

def discover(issuer: str) -> dict:
    """Discover OIDC/JWKS metadata, with RFC 8414 AS metadata fallback.

    External OIDC issuers normally expose ``openid-configuration``. Tokens
    minted by this service expose RFC 8414 OAuth authorization-server metadata
    at the endpoint implemented by ``app.main`` instead.
    """
    issuer = normalize_issuer(issuer)
    try:
        metadata = _get_json(f'{issuer}/.well-known/openid-configuration')
    except DiscoveryError as oidc_error:
        try:
            metadata = _get_json(f'{issuer}/.well-known/oauth-authorization-server')
        except DiscoveryError:
            raise oidc_error
    if metadata.get('issuer', '').rstrip('/') != issuer:
        raise DiscoveryError('issuer metadata does not match configured issuer')
    jwks_uri = metadata.get('jwks_uri')
    if not isinstance(jwks_uri, str): raise DiscoveryError('issuer metadata has no jwks_uri')
    parsed = urlparse(jwks_uri)
    if parsed.scheme != urlparse(issuer).scheme: raise DiscoveryError('jwks_uri scheme mismatch')
    introspection_uri = metadata.get('introspection_endpoint')
    if introspection_uri is not None:
        if not isinstance(introspection_uri, str) or not introspection_uri:
            raise DiscoveryError('introspection_endpoint is malformed')
        ip = urlparse(introspection_uri)
        if ip.username or ip.password or ip.query or ip.fragment or not ip.netloc or ip.scheme != parsed.scheme:
            raise DiscoveryError('introspection_endpoint is unsafe')
    return metadata

def fetch_jwks(metadata: dict) -> dict:
    jwks_uri = metadata.get('jwks_uri')
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise DiscoveryError('issuer metadata has no jwks_uri')
    parsed = urlparse(jwks_uri)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.netloc:
        raise DiscoveryError('jwks_uri is malformed')
    keys = _get_json(jwks_uri)
    if not isinstance(keys.get('keys'), list): raise DiscoveryError('JWKS response is invalid')
    return keys
