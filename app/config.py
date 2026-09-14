from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    as_issuer: str = 'http://localhost:8000'
    token_client_id: str = 'tokenexchange'
    token_client_secret: str = 'change-me'
    token_ttl_seconds: int = 300
    token_max_ttl_seconds: int = 300
    signing_key_path: str = './dev-signing-key.pem'
    signing_key_algorithm: str = 'RS256'
    signing_key_id: str = 'as-development'
    clock_skew_seconds: int = 30
    allow_insecure_http: bool = False
    p1az_mode: str = 'enforce'
    p1az_auth_base: str = 'https://auth.pingone.com'
    p1az_api_base: str = 'https://api.pingone.com/v1'
    p1az_environment_id: str = ''
    p1az_decision_endpoint_id: str = ''
    p1az_worker_client_id: str = ''
    p1az_worker_client_secret: str = ''
    p1az_timeout_seconds: float = 5.0
    p1az_token_safety_seconds: int = 60

@lru_cache
def get_settings() -> Settings:
    return Settings()
