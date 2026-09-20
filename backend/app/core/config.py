from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = Field(default='development', alias='APP_ENV')
    host: str = Field(default='0.0.0.0', alias='HOST')
    port: int = Field(default=5000, alias='PORT')
    database_url: str = Field(default='sqlite:///./cybershield.db', alias='DATABASE_URL')
    report_storage_root: str = Field(default='reports/generated', alias='REPORT_STORAGE_ROOT')
    db_pool_size: int = Field(default=5, alias='DB_POOL_SIZE')
    db_max_overflow: int = Field(default=10, alias='DB_MAX_OVERFLOW')
    jwt_secret: str = Field(default='replace-with-a-secure-random-secret-at-least-32-characters-long', alias='JWT_SECRET')
    jwt_algorithm: str = Field(default='HS256', alias='JWT_ALGORITHM')
    access_token_expire_minutes: int = Field(default=30, alias='ACCESS_TOKEN_EXPIRE_MINUTES')
    cors_origins: List[str] = Field(default_factory=lambda: ['http://localhost:3000'], alias='CORS_ORIGINS')
    enable_legacy_user_header: bool = Field(default=False, alias='ENABLE_LEGACY_USER_HEADER')
    scanner_enabled: bool = Field(default=True, alias='SCANNER_ENABLED')
    scanner_connect_timeout: float = Field(default=5.0, alias='SCANNER_CONNECT_TIMEOUT')
    scanner_read_timeout: float = Field(default=10.0, alias='SCANNER_READ_TIMEOUT')
    scanner_total_timeout: float = Field(default=20.0, alias='SCANNER_TOTAL_TIMEOUT')
    scanner_max_redirects: int = Field(default=3, alias='SCANNER_MAX_REDIRECTS')
    scanner_max_response_bytes: int = Field(default=200000, alias='SCANNER_MAX_RESPONSE_BYTES')
    scanner_max_requests_per_scan: int = Field(default=5, alias='SCANNER_MAX_REQUESTS_PER_SCAN')
    scanner_max_concurrent_scans: int = Field(default=3, alias='SCANNER_MAX_CONCURRENT_SCANS')
    ai_provider: str = Field(default='mock', alias='AI_PROVIDER')
    ai_api_key: str = Field(default='', alias='AI_API_KEY')
    ai_model: str = Field(default='local-mock', alias='AI_MODEL')
    ai_timeout_seconds: int = Field(default=10, alias='AI_TIMEOUT_SECONDS')
    ai_max_output_tokens: int = Field(default=600, alias='AI_MAX_OUTPUT_TOKENS')
    log_level: str = Field(default='INFO', alias='LOG_LEVEL')

    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
        extra='ignore',
        case_sensitive=False,
    )

    @field_validator('jwt_secret')
    @classmethod
    def validate_jwt_secret(cls, value: str) -> str:
        if len(value) < 32:
            raise ValueError('JWT_SECRET must be at least 32 characters long.')
        return value

    @model_validator(mode='after')
    def validate_production_security(self) -> 'Settings':
        if self.app_env.lower() in {'production', 'prod'} and self.jwt_secret == 'replace-with-a-secure-random-secret-at-least-32-characters-long':
            raise ValueError('JWT_SECRET must be explicitly configured outside development and test environments.')
        if self.app_env.lower() in {'production', 'prod'} and '*' in self.cors_allowlist:
            raise ValueError('Wildcard CORS origins are not allowed in production.')
        return self

    @property
    def cors_allowlist(self) -> list[str]:
        origins = self.cors_origins
        if isinstance(origins, str):
            origins = [origin.strip() for origin in origins.split(',')]
        return [origin.strip() for origin in origins if origin.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
