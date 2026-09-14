import pytest

from app.discovery import discover, DiscoveryError


class FakeResponse:
    def __init__(self, status, body):
        self.status_code = status
        self.content = b'{}' if body is None else __import__('json').dumps(body).encode()
    def json(self):
        import json as _json
        return _json.loads(self.content)


def _get_json(monkeypatch, responses):
    """Point _get_json at a URL-keyed response map; record the fetched URLs."""
    calls = []
    def fake(url):
        calls.append(url)
        response = responses[url]
        if isinstance(response, Exception):
            raise response
        return response
    monkeypatch.setattr('app.discovery._get_json', fake)
    return calls


def test_oidc_metadata_is_preferred(monkeypatch):
    # Routing/SSRF guards are not under test here.
    monkeypatch.setattr('app.discovery.normalize_issuer', lambda issuer: issuer.rstrip('/'))
    calls = _get_json(monkeypatch, {
        'https://issuer.example/.well-known/openid-configuration':
            {'issuer': 'https://issuer.example', 'jwks_uri': 'https://issuer.example/jwks'},
    })
    metadata = discover('https://issuer.example')
    assert metadata['jwks_uri'] == 'https://issuer.example/jwks'
    assert calls == ['https://issuer.example/.well-known/openid-configuration']


def test_rfc8414_fallback_when_oidc_metadata_is_absent(monkeypatch):
    # Tokens minted by this service expose RFC 8414 metadata only, so a
    # follow-on exchange's JWT-declared subject must be discoverable via the
    # fallback endpoint.
    monkeypatch.setattr('app.discovery.normalize_issuer', lambda issuer: issuer.rstrip('/'))
    calls = _get_json(monkeypatch, {
        'https://issuer.example/.well-known/openid-configuration':
            DiscoveryError('issuer metadata unavailable'),
        'https://issuer.example/.well-known/oauth-authorization-server':
            {'issuer': 'https://issuer.example', 'jwks_uri': 'https://issuer.example/as/jwks'},
    })
    metadata = discover('https://issuer.example')
    assert metadata['jwks_uri'] == 'https://issuer.example/as/jwks'
    assert calls == [
        'https://issuer.example/.well-known/openid-configuration',
        'https://issuer.example/.well-known/oauth-authorization-server',
    ]


def test_fallback_failure_raises_original_error(monkeypatch):
    # When both endpoints fail, the OIDC error is the one reported.
    monkeypatch.setattr('app.discovery.normalize_issuer', lambda issuer: issuer.rstrip('/'))
    _get_json(monkeypatch, {
        'https://issuer.example/.well-known/openid-configuration':
            DiscoveryError('issuer metadata is not JSON'),
        'https://issuer.example/.well-known/oauth-authorization-server':
            DiscoveryError('issuer metadata unavailable'),
    })
    with pytest.raises(DiscoveryError, match='not JSON'):
        discover('https://issuer.example')


def test_issuer_mismatch_fails_even_via_fallback(monkeypatch):
    # Metadata that does not echo the configured issuer is rejected on both
    # discovery paths.
    monkeypatch.setattr('app.discovery.normalize_issuer', lambda issuer: issuer.rstrip('/'))
    _get_json(monkeypatch, {
        'https://issuer.example/.well-known/openid-configuration':
            DiscoveryError('issuer metadata unavailable'),
        'https://issuer.example/.well-known/oauth-authorization-server':
            {'issuer': 'https://other.example', 'jwks_uri': 'https://other.example/jwks'},
    })
    with pytest.raises(DiscoveryError, match='does not match'):
        discover('https://issuer.example')
