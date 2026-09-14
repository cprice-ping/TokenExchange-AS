from __future__ import annotations

import time
from urllib.parse import urlparse

import jwt
from jwt import PyJWK

from .discovery import discover, fetch_jwks, DiscoveryError, normalize_issuer

JWT_TYPE = 'urn:ietf:params:oauth:token-type:jwt'
ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'
# Kept as a request-validation compatibility constant; dispatch below is
# strictly by the declared token type.
JWT_TYPES = {JWT_TYPE, ACCESS_TOKEN_TYPE}
ALGORITHMS = {'RS256', 'ES256'}


def _claims_from_unverified_token(token: str, *, actor: bool) -> dict:
    """Decode token claims without verification, for claim propagation only.

    Declared ``access_token`` inputs are validated by PingOne Authorize's
    policy (which performs RFC 7662 introspection at the issuer); the token
    is sent there in the decision parameters. Locally this decode supplies
    only the claim values copied into the minted token — it is never a
    trust or authentication decision.
    """
    try:
        claims = jwt.decode(token, options={'verify_signature': False, 'verify_exp': False})
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise ValueError(f'access token is not a decodable JWT: {exc}') from exc
    return _normalize_claims(claims, actor=actor)


def _issuer_from_unverified_token(token: str) -> str:
    """Read issuer only to route discovery; this is never an auth decision."""
    try:
        claims = jwt.decode(token, options={'verify_signature': False, 'verify_exp': False})
        issuer = claims.get('iss')
        if not isinstance(issuer, str) or not issuer:
            raise ValueError('missing issuer')
        return normalize_issuer(issuer)
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise ValueError(f'issuer routing failed: {exc}') from exc


def _audience_is_well_formed(claims: dict) -> None:
    audience = claims.get('aud')
    if audience is None:
        return
    if isinstance(audience, str):
        if not audience:
            raise ValueError('token audience is malformed')
        return
    if isinstance(audience, list) and all(isinstance(item, str) and item for item in audience):
        return
    raise ValueError('token audience is malformed')


def _normalize_claims(claims: dict, *, actor: bool) -> dict:
    _audience_is_well_formed(claims)
    if claims.get('iat') is not None and claims['iat'] > time.time() + 30:
        raise ValueError('token issued in the future')
    if not actor:
        if not isinstance(claims.get('sub'), str) or not claims['sub']:
            raise ValueError('subject token claims are not eligible for exchange')
        existing_actor = claims.get('act')
        if existing_actor is not None and (not isinstance(existing_actor, dict) or not isinstance(existing_actor.get('sub'), str) or not existing_actor['sub']):
            raise ValueError('subject token actor claim is malformed')
        return claims
    nested_actor = claims.get('act')
    if isinstance(nested_actor, dict) and isinstance(nested_actor.get('sub'), str) and nested_actor['sub']:
        normalized = dict(claims)
        normalized['sub'] = nested_actor['sub']
        return normalized
    if isinstance(claims.get('sub'), str) and claims['sub']:
        return claims
    # PingOne client-credentials JWTs name the client in client_id and omit
    # sub; accept that as the actor subject. Subjects (actor=False) never
    # get this fallback: a client token must never mint a token about a
    # person.
    client_id = claims.get('client_id')
    if isinstance(client_id, str) and client_id:
        normalized = dict(claims)
        normalized['sub'] = client_id
        return normalized
    raise ValueError('actor token has no actor subject')


def validate_token(token: str, token_type: str, *, actor: bool = False) -> dict:
    """Validate a token by its declared RFC 8693 type.

    JWT inputs are cryptographically validated: the unverified ``iss`` is
    used only to locate OIDC discovery/JWKS, the discovered metadata must
    echo that issuer, and PyJWT verifies the final token against it.
    Declared ``access_token`` inputs are opaque to this service: no local
    validation is possible, so the raw value is sent to PingOne Authorize
    for policy validation (including introspection at the issuer) and only
    its claims are decoded locally for propagation into the minted token.
    """
    if token_type not in JWT_TYPES or not token:
        raise ValueError('invalid token')
    if token_type == ACCESS_TOKEN_TYPE:
        return _claims_from_unverified_token(token, actor=actor)

    issuer = _issuer_from_unverified_token(token)
    from .config import get_settings
    try:
        metadata = discover(issuer)
        jwks = fetch_jwks(metadata)
        header = jwt.get_unverified_header(token)
        algorithm = header.get('alg')
        kid = header.get('kid')
        if algorithm not in ALGORITHMS or not kid:
            raise ValueError('unsupported token algorithm')
        key_data = next((key for key in jwks['keys'] if key.get('kid') == kid), None)
        if not key_data:
            raise ValueError('unknown signing key')
        # PyJWT 2.10 infers the algorithm from the JWK when the provider
        # omits the optional JWK ``alg`` member (PingOne does this). Do not
        # pass the removed ``algorithm_name`` constructor argument.
        jwk = PyJWK(key_data)
        if jwk.algorithm_name != algorithm:
            raise ValueError('token algorithm does not match signing key')
        key = jwk.key
        claims = jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            issuer=issuer,
            leeway=get_settings().clock_skew_seconds,
            options={
                'require': ['exp', 'iat'] + ([] if actor else ['sub']),
                'verify_aud': False,
            },
        )
    except (jwt.PyJWTError, DiscoveryError, KeyError, TypeError, ValueError) as exc:
        raise ValueError(f'cryptographic validation failed: {exc}') from exc

    return _normalize_claims(claims, actor=actor)
