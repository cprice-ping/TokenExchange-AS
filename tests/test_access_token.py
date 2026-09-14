import base64
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app.validation import validate_token, ACCESS_TOKEN_TYPE, JWT_TYPE


def test_access_token_decodes_claims_without_verification():
    claims = jwt.encode({'iss': 'https://issuer.example', 'sub': 'human', 'aud': 'gateway'}, '0123456789abcdef0123456789abcdef', algorithm='HS256')
    result = validate_token(claims, ACCESS_TOKEN_TYPE)
    assert result['sub'] == 'human'
    assert result['iss'] == 'https://issuer.example'


def test_access_token_is_never_cryptographically_validated():
    # Signed with a throwaway key: signature verification must not happen.
    token = jwt.encode({'iss': 'https://issuer.example', 'sub': 'human'}, '0123456789abcdef0123456789abcdef', algorithm='HS256')
    result = validate_token(token, ACCESS_TOKEN_TYPE)
    assert result['sub'] == 'human'


def test_garbage_access_token_fails_closed():
    with pytest.raises(ValueError, match='not a decodable JWT'):
        validate_token('not-a-jwt', ACCESS_TOKEN_TYPE)


def test_access_token_actor_uses_act_claim():
    token = jwt.encode({'iss': 'https://issuer.example', 'sub': 'human', 'act': {'sub': 'agent'}}, '0123456789abcdef0123456789abcdef', algorithm='HS256')
    result = validate_token(token, ACCESS_TOKEN_TYPE, actor=True)
    assert result['sub'] == 'agent'


def test_access_token_actor_without_subject_fails():
    # Neither act.sub nor sub: no actor subject to propagate.
    token = jwt.encode({'iss': 'https://issuer.example'}, '0123456789abcdef0123456789abcdef', algorithm='HS256')
    with pytest.raises(ValueError, match='no actor subject'):
        validate_token(token, ACCESS_TOKEN_TYPE, actor=True)


def test_pingone_client_credentials_actor_uses_client_id():
    # PingOne CC JWTs name the client in client_id and omit sub; the actor
    # subject falls back to client_id (bridge clients act on the person's
    # behalf). A client_id fallback must NOT rescue a subject token.
    token = jwt.encode({'iss': 'https://issuer.example', 'client_id': 'bridge-client'}, '0123456789abcdef0123456789abcdef', algorithm='HS256')
    assert validate_token(token, ACCESS_TOKEN_TYPE, actor=True)['sub'] == 'bridge-client'
    with pytest.raises(ValueError, match='not eligible'):
        validate_token(token, ACCESS_TOKEN_TYPE)


def test_subject_access_token_requires_subject():
    token = jwt.encode({'iss': 'https://issuer.example'}, '0123456789abcdef0123456789abcdef', algorithm='HS256')
    with pytest.raises(ValueError, match='not eligible'):
        validate_token(token, ACCESS_TOKEN_TYPE)


def _es256_jwk(private_key, kid='test-es256'):
    def b64u(value: int) -> str:
        return base64.urlsafe_b64encode(value.to_bytes(32, 'big')).rstrip(b'=').decode()
    numbers = private_key.public_key().public_numbers()
    return {'kty': 'EC', 'kid': kid, 'crv': 'P-256', 'x': b64u(numbers.x), 'y': b64u(numbers.y)}


def test_jwt_type_still_verifies_signature(monkeypatch):
    # JWT-declared inputs keep the cryptographic path: a valid signature is
    # accepted and a forged one (tampered signature, wrong key) fails closed.
    private_key = ec.generate_private_key(ec.SECP256R1())
    kid = 'test-es256'
    jwk = _es256_jwk(private_key, kid=kid)
    # Routing/SSRF guards are not under test here; the mocked discovery path
    # verifies only signature selection and verification.
    monkeypatch.setattr('app.validation.normalize_issuer', lambda issuer: issuer.rstrip('/'))
    monkeypatch.setattr('app.validation.discover', lambda issuer: {'issuer': issuer, 'jwks_uri': f'{issuer}/jwks'})
    monkeypatch.setattr('app.validation.fetch_jwks', lambda metadata: {'keys': [jwk]})
    now = int(time.time())
    claims = {'iss': 'https://issuer.example', 'sub': 'human', 'iat': now, 'exp': now + 300}
    valid = jwt.encode(claims, private_key, algorithm='ES256', headers={'kid': kid})
    assert validate_token(valid, JWT_TYPE)['sub'] == 'human'
    forged = jwt.encode(claims, ec.generate_private_key(ec.SECP256R1()), algorithm='ES256', headers={'kid': kid})
    with pytest.raises(ValueError, match='cryptographic validation failed'):
        validate_token(forged, JWT_TYPE)
