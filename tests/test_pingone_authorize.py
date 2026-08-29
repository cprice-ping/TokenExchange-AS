import base64
import httpx
import pytest
from app.config import get_settings
from app.pingone_authorize import PingOneAuthorize, P1AZError

class FakeResponse:
    def __init__(self, status, body, headers=None):
        self.status_code, self.body = status, body
        self.headers = headers if headers is not None else FakeHeaders()
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

class FakeHeaders:
    def __init__(self, retry_after=None): self.retry_after = retry_after
    def get(self, name):
        return self.retry_after if name.lower() == 'retry-after' else None

def _configure(monkeypatch):
    monkeypatch.setenv('P1AZ_ENVIRONMENT_ID', 'env')
    monkeypatch.setenv('P1AZ_DECISION_ENDPOINT_ID', 'decision')
    monkeypatch.setenv('P1AZ_WORKER_CLIENT_ID', 'worker')
    monkeypatch.setenv('P1AZ_WORKER_CLIENT_SECRET', 'secret')
    get_settings.cache_clear()

def test_429_is_retried_with_backoff(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr('app.pingone_authorize.time.sleep', lambda seconds: None)
    decision_calls = []
    def post(url, **kwargs):
        if url.endswith('/as/token'): return FakeResponse(200, {'access_token': 'worker-token', 'expires_in': 300})
        decision_calls.append(url)
        if len(decision_calls) < 3: return FakeResponse(429, {'error': 'rate_limited'})
        return FakeResponse(200, {'decision': 'PERMIT'})
    monkeypatch.setattr(httpx, 'post', post)
    result = PingOneAuthorize().decide(subject={'sub':'human','iss':'https://human.example'}, actor=None, subject_token_type='jwt', actor_token_type=None)
    assert result['decision'] == 'PERMIT'
    assert len(decision_calls) == 3

def test_429_honors_retry_after_header(monkeypatch):
    _configure(monkeypatch)
    sleeps = []
    monkeypatch.setattr('app.pingone_authorize.time.sleep', lambda seconds: sleeps.append(seconds))
    calls = []
    def post(url, **kwargs):
        calls.append(url)
        if url.endswith('/as/token'): return FakeResponse(200, {'access_token': 'worker-token', 'expires_in': 300})
        if len([u for u in calls if u.endswith('/decision')]) < 2:
            return FakeResponse(429, {'error': 'rate_limited'}, headers=FakeHeaders(retry_after='1'))
        return FakeResponse(200, {'decision': 'PERMIT'})
    monkeypatch.setattr(httpx, 'post', post)
    PingOneAuthorize().decide(subject={'sub':'human','iss':'https://human.example'}, actor=None, subject_token_type='jwt', actor_token_type=None)
    assert sleeps == [1.0]

def test_persistent_429_fails_closed(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr('app.pingone_authorize.time.sleep', lambda seconds: None)
    def post(url, **kwargs):
        if url.endswith('/as/token'): return FakeResponse(200, {'access_token': 'worker-token', 'expires_in': 300})
        return FakeResponse(429, {'error': 'rate_limited'})
    monkeypatch.setattr(httpx, 'post', post)
    with pytest.raises(P1AZError, match='unavailable'):
        PingOneAuthorize().decide(subject={'sub':'human','iss':'https://human.example'}, actor=None, subject_token_type='jwt', actor_token_type=None)
