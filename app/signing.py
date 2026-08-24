from __future__ import annotations
import base64, time, uuid
from pathlib import Path
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from .config import get_settings

class Signer:
    def __init__(self):
        settings = get_settings(); self.algorithm = settings.signing_key_algorithm
        self.kid = settings.signing_key_id
        if not self.kid:
            raise RuntimeError('SIGNING_KEY_ID must be configured')
        path = Path(settings.signing_key_path)
        if not path.exists():
            raise RuntimeError(f'signing key is not available at {path}')
        self.private_key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        self.public_key = self.private_key.public_key()

    def mint(self, *, subject: str, actor: str | None, audience: str, scope: str, ttl: int) -> str:
        now = int(time.time())
        claims = {'iss': get_settings().as_issuer.rstrip('/'), 'sub': subject, 'aud': audience, 'iat': now, 'exp': now + ttl, 'jti': uuid.uuid4().hex, 'scope': scope}
        if actor:
            claims['act'] = {'sub': actor}
        return jwt.encode(claims, self.private_key, algorithm=self.algorithm, headers={'kid': self.kid, 'typ': 'JWT'})

    def jwks(self) -> dict:
        numbers = self.public_key.public_numbers()
        def b64(value: int) -> str:
            raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
            return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
        return {'keys': [{'kty': 'RSA', 'kid': self.kid, 'use': 'sig', 'alg': self.algorithm, 'n': b64(numbers.n), 'e': b64(numbers.e)}]}
