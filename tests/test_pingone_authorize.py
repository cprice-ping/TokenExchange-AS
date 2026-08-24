import base64
import httpx
import pytest
from app.config import get_settings
from app.pingone_authorize import PingOneAuthorize, P1AZError

class FakeResponse:
    def __init__(self, status, body): self.status_code, self.body = status, body
    def json(self): return self.body

def test_worker_request_has_no_scope(monkeypatch):
    monkeypatch.setenv('P1AZ_ENVIRONMENT_ID', 'env')
    monkeypatch.setenv('P1AZ_DECISION_ENDPOINT_ID', 'decision')
    monkeypatch.setenv('P1AZ_WORKER_CLIENT_ID', 'worker')
    monkeypatch.setenv('P1AZ_WORKER_CLIENT_SECRET', 'secret')
    get_settings.cache_clear()
    calls = []
    def post(url, **kwargs):
        calls.append((url, kwargs)); return FakeResponse(200, {'access_token': 'worker-token', 'expires_in': 300})
    monkeypatch.setattr(httpx, 'post', post)
    token = PingOneAuthorize()._worker_token()
    assert token == 'worker-token'
    url, kwargs = calls[0]
    assert url.endswith('/env/as/token')
    assert kwargs['data'] == {'grant_type': 'client_credentials'}
    assert 'scope' not in kwargs['data']
    assert base64.b64decode(kwargs['headers']['Authorization'][6:]).decode() == 'worker:secret'

def test_decision_parameters_are_namespaced(monkeypatch):
    monkeypatch.setenv('P1AZ_ENVIRONMENT_ID', 'env')
    monkeypatch.setenv('P1AZ_DECISION_ENDPOINT_ID', 'decision')
    monkeypatch.setenv('P1AZ_WORKER_CLIENT_ID', 'worker')
    monkeypatch.setenv('P1AZ_WORKER_CLIENT_SECRET', 'secret')
    get_settings.cache_clear()
    calls = []
    def post(url, **kwargs):
        calls.append((url, kwargs))
        if url.endswith('/as/token'): return FakeResponse(200, {'access_token': 'worker-token', 'expires_in': 300})
        return FakeResponse(200, {'decision': 'PERMIT'})
    monkeypatch.setattr(httpx, 'post', post)
    PingOneAuthorize().decide(subject={'sub':'human','iss':'https://human.example'}, actor={'sub':'agent','iss':'https://agent.example','scope':['a','b'],'aud':['z','y']}, subject_token_type='jwt', actor_token_type='jwt')
    payload = calls[-1][1]['json']['parameters']
    assert payload == {
        'Request.TokenExchange.Subject.sub': 'human',
        'Request.TokenExchange.Subject.iss': 'https://human.example',
        'Request.TokenExchange.Actor.sub': 'agent',
        'Request.TokenExchange.Actor.iss': 'https://agent.example',
        'Request.TokenExchange.scope': '',
        'Request.TokenExchange.aud': '',
    }

def test_denied_decision_fails_closed(monkeypatch):
    monkeypatch.setenv('P1AZ_ENVIRONMENT_ID', 'env')
    monkeypatch.setenv('P1AZ_DECISION_ENDPOINT_ID', 'decision')
    monkeypatch.setenv('P1AZ_WORKER_CLIENT_ID', 'worker')
    monkeypatch.setenv('P1AZ_WORKER_CLIENT_SECRET', 'secret')
    get_settings.cache_clear()
    def post(url, **kwargs):
        if url.endswith('/as/token'): return FakeResponse(200, {'access_token': 'worker-token', 'expires_in': 300})
        return FakeResponse(200, {'decision': 'DENY'})
    monkeypatch.setattr(httpx, 'post', post)
    with pytest.raises(P1AZError, match='denied'):
        PingOneAuthorize().decide(subject={'sub':'human','iss':'https://human.example'}, actor=None, subject_token_type='jwt', actor_token_type=None)
