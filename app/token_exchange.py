from __future__ import annotations
import base64, binascii, hmac, logging, uuid
from dataclasses import dataclass
from fastapi import APIRouter, Form, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from .config import get_settings
from .signing import Signer
from .validation import validate_token, JWT_TYPES, ACCESS_TOKEN_TYPE
from .pingone_authorize import P1AZError, p1az

logger = logging.getLogger('token-exchange')
GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange'
ACCESS = 'urn:ietf:params:oauth:token-type:access_token'
router = APIRouter()
signer = Signer()

@dataclass(frozen=True)
class ExchangeClient:
    client_id: str
    max_ttl_seconds: int

def _safe_category(error: Exception) -> str:
    text = str(error).lower()
    for category in ('introspection_source_missing', 'introspection_inactive', 'introspection_unavailable', 'introspection', 'issuer', 'jwks', 'signature', 'algorithm', 'audience', 'subject', 'actor', 'discovery', 'key', 'token'):
        if category in text: return category
    return 'validation'

def oauth_error(code: str, description: str, status: int = 400):
    return JSONResponse({'error': code, 'error_description': description}, status_code=status, headers={'Cache-Control': 'no-store'})

def client_auth(authorization: str | None) -> ExchangeClient:
    settings = get_settings()
    if not authorization or not authorization.lower().startswith('basic '):
        logger.warning(
            'token client authentication failed reason=missing_or_non_basic_header present=%s',
            bool(authorization),
        )
        raise HTTPException(401, detail='invalid_client', headers={'WWW-Authenticate': 'Basic realm="token"'})
    try:
        raw = base64.b64decode(authorization[6:], validate=True).decode()
        client_id, secret = raw.split(':', 1)
    except (ValueError, UnicodeError, binascii.Error):
        logger.warning('token client authentication failed reason=malformed_basic_header')
        raise HTTPException(401, detail='invalid_client', headers={'WWW-Authenticate': 'Basic realm="token"'})
    id_matches = hmac.compare_digest(client_id, settings.token_client_id)
    secret_matches = hmac.compare_digest(secret, settings.token_client_secret)
    if not (id_matches and secret_matches):
        logger.warning(
            'token client authentication failed reason=credential_mismatch client_id=%s id_matches=%s secret_matches=%s supplied_secret_length=%d configured_secret_length=%d',
            client_id,
            id_matches,
            secret_matches,
            len(secret),
            len(settings.token_client_secret),
        )
        raise HTTPException(401, detail='invalid_client', headers={'WWW-Authenticate': 'Basic realm="token"'})
    logger.info('token client authenticated client_id=%s', client_id)
    return ExchangeClient(settings.token_client_id, min(settings.token_ttl_seconds, settings.token_max_ttl_seconds))

@router.post('/as/token')
def token_exchange(request: Request, grant_type: str = Form(''), subject_token: str = Form(''), subject_token_type: str = Form(''), actor_token: str | None = Form(None), actor_token_type: str | None = Form(None), requested_token_type: str | None = Form(None), resource: str | None = Form(None), audience: str | None = Form(None), scope: str | None = Form(None), authorization: str | None = Header(None)):
    correlation_id = request.headers.get('x-correlation-id') or uuid.uuid4().hex
    try: client = client_auth(authorization)
    except HTTPException as exc: return oauth_error('invalid_client', 'client authentication failed', exc.status_code)
    if grant_type != GRANT or not subject_token or not subject_token_type: return oauth_error('invalid_request', 'required token exchange parameters are missing')
    if requested_token_type and requested_token_type != ACCESS: return oauth_error('unsupported_token_type', 'requested token type is not supported')
    if subject_token_type not in JWT_TYPES or (actor_token_type and actor_token_type not in JWT_TYPES): return oauth_error('invalid_grant', 'the supplied token is not valid')
    if bool(actor_token) != bool(actor_token_type): return oauth_error('invalid_request', 'actor token type must accompany actor token')
    target = audience or resource or ''
    if not target: return oauth_error('invalid_target', 'audience or resource is required')
    requested_scope = ' '.join(sorted(set((scope or '').split())))
    if not requested_scope: return oauth_error('invalid_target', 'scope is required')
    subject_claims = None
    actor_claims = None
    try:
        subject_claims = validate_token(subject_token, subject_token_type, introspection_issuer=get_settings().introspection_issuer)
        logger.info('token exchange token validated correlation_id=%s role=subject token_type=%s issuer=%s', correlation_id, subject_token_type, subject_claims.get('iss', '<introspection>'))
        actor_claims = validate_token(actor_token, actor_token_type or '', actor=True, introspection_issuer=get_settings().introspection_issuer) if actor_token else None
        if actor_claims is not None: logger.info('token exchange token validated correlation_id=%s role=actor token_type=%s issuer=%s', correlation_id, actor_token_type, actor_claims.get('iss', '<introspection>'))
    except ValueError as exc:
        role = 'actor' if subject_claims is not None and actor_token else 'subject'
        logger.warning('token exchange rejected correlation_id=%s role=%s category=%s', correlation_id, role, _safe_category(exc))
        return oauth_error('invalid_grant', 'the supplied token is not valid')
    if get_settings().p1az_mode == 'disabled': return oauth_error('temporarily_unavailable', 'token exchange policy is unavailable', 503)
    try:
        p1az.decide(subject=subject_claims, actor=actor_claims, subject_token_type=subject_token_type, actor_token_type=actor_token_type, requested_audience=target, requested_scope=requested_scope, client_id=client.client_id)
    except P1AZError as exc:
        logger.warning('token exchange P1AZ failure correlation_id=%s category=%s', correlation_id, exc.category)
        if exc.category == 'denied': return oauth_error('access_denied', 'token exchange denied', 403)
        return oauth_error('temporarily_unavailable', 'token exchange policy is unavailable', 503)
    ttl = client.max_ttl_seconds
    prior_actor = subject_claims.get('act', {}).get('sub') if isinstance(subject_claims.get('act'), dict) else None
    minted = signer.mint(subject=subject_claims['sub'], actor=actor_claims['sub'] if actor_claims else prior_actor, audience=target, scope=requested_scope, ttl=ttl)
    return JSONResponse({'access_token': minted, 'issued_token_type': ACCESS, 'token_type': 'Bearer', 'expires_in': ttl, 'scope': requested_scope}, headers={'Cache-Control': 'no-store'})
