import logging

from fastapi import FastAPI
from .token_exchange import router as token_router
from .config import get_settings

logging.basicConfig(level=logging.INFO)
_service_handler = logging.StreamHandler()
_service_handler.setFormatter(logging.Formatter('%(levelname)s:     %(name)s: %(message)s'))
for _logger_name in ('token-exchange', 'httpx'):
    _service_logger = logging.getLogger(_logger_name)
    _service_logger.handlers.clear()
    _service_logger.addHandler(_service_handler)
    _service_logger.propagate = False
    _service_logger.setLevel(logging.INFO)

app = FastAPI(title='RFC 8693 Token Exchange AS', version='0.1.0')
app.include_router(token_router)

@app.get('/healthz')
def health(): return {'status': 'ok'}

@app.get('/as/jwks')
def jwks():
    from .token_exchange import signer
    return signer.jwks()

@app.get('/.well-known/oauth-authorization-server')
def metadata():
    issuer = get_settings().as_issuer.rstrip('/')
    return {'issuer': issuer, 'token_endpoint': f'{issuer}/as/token', 'jwks_uri': f'{issuer}/as/jwks', 'grant_types_supported': ['urn:ietf:params:oauth:grant-type:token-exchange'], 'token_endpoint_auth_methods_supported': ['client_secret_basic'], 'token_endpoint_auth_signing_alg_values_supported': ['RS256'], 'scopes_supported': ['use_gateway']}
