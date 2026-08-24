import base64
import httpx
import pytest
from app.config import get_settings
from app.introspection import introspect, IntrospectionError
from app.validation import validate_token, ACCESS_TOKEN_TYPE

class FakeResponse:
    def __init__(self, status, body): self.status_code, self.body = status, body
    def json(self): return self.body

def setup_env(monkeypatch):
    monkeypatch.setenv('INTROSPECTION_CLIENT_ID', 'introspect-client')
    monkeypatch.setenv('INTROSPECTION_CLIENT_SECRET', 'introspect-secret')
    get_settings.cache_clear()

def test_active_introspection_uses_basic_and_hint(monkeypatch):
    setup_env(monkeypatch)
    monkeypatch.setattr('app.introspection.discover', lambda issuer: {'issuer': issuer, 'introspection_endpoint': 'https://issuer.example/introspect'})
    calls=[]
    def post(url, **kwargs): calls.append((url, kwargs)); return FakeResponse(200, {'active': True, 'iss': 'https://issuer.example', 'sub': 'human', 'scope': 'read'})
    monkeypatch.setattr(httpx, 'post', post)
    claims = introspect('opaque-token', issuer='https://issuer.example')
    assert claims['sub'] == 'human'
    assert calls[0][1]['data'] == {'token': 'opaque-token', 'token_type_hint': 'access_token'}
    assert base64.b64decode(calls[0][1]['headers']['Authorization'][6:]).decode() == 'introspect-client:introspect-secret'

def test_access_token_type_always_introspects_even_when_jwt_shaped(monkeypatch):
    setup_env(monkeypatch)
    calls = []
    monkeypatch.setattr('app.validation.introspect', lambda token, issuer: calls.append((token, issuer)) or {'iss': issuer, 'sub': 'human'})
    monkeypatch.setattr('app.validation.discover', lambda issuer: (_ for _ in ()).throw(AssertionError('JWKS must not be fetched')))
    claims = validate_token('header.payload.signature', ACCESS_TOKEN_TYPE, introspection_issuer='https://issuer.example')
    assert claims['sub'] == 'human'
    assert calls == [('header.payload.signature', 'https://issuer.example')]


def test_inactive_fails_closed(monkeypatch):
    setup_env(monkeypatch)
    monkeypatch.setattr('app.introspection.discover', lambda issuer: {'issuer': issuer, 'introspection_endpoint': 'https://issuer.example/introspect'})
    monkeypatch.setattr(httpx, 'post', lambda *args, **kwargs: FakeResponse(200, {'active': False}))
    with pytest.raises(IntrospectionError, match='inactive'):
        introspect('opaque-token', issuer='https://issuer.example')
