import pytest
from fastapi.testclient import TestClient
from app.config import get_settings

@pytest.fixture
def client(tmp_path, monkeypatch):
    # Generate a test key explicitly; production deployments must mount one.
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / 'key.pem'
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    monkeypatch.setenv('SIGNING_KEY_PATH', str(path))
    monkeypatch.setenv('ALLOW_INSECURE_HTTP', 'true')
    get_settings.cache_clear()
    from app.main import app
    with TestClient(app) as c: yield c

def test_health(client): assert client.get('/healthz').json() == {'status': 'ok'}
def test_metadata(client):
    response = client.get('/.well-known/oauth-authorization-server')
    assert response.status_code == 200 and response.json()['grant_types_supported']
def test_removed_admin_route_is_not_exposed(client): assert client.get('/admin/issuers').status_code == 404
def test_jwks(client): assert client.get('/as/jwks').json()['keys'][0]['alg'] == 'RS256'
