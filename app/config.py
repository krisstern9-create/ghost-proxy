"""
Ghost Proxy - Configuration Management

Centralized settings with validation, environment variable support,
and secure defaults for production deployment.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator
from typing import List, Optional
from functools import lru_cache
import secrets

# ============================================
# SETTINGS CLASS
# ============================================

class Settings(BaseSettings):
    """
    Application settings with validation.
    
    Loads from:
    1. Environment variables
    2. .env file
    3. Default values
    """
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # ============================================
    # SERVER CONFIGURATION
    # ============================================
    
    HOST: str = Field(default="0.0.0.0", description="Server host")
    PORT: int = Field(default=8000, ge=1, le=65535, description="Server port")
    DEBUG: bool = Field(default=False, description="Debug mode")
    
    # ============================================
    # SECURITY
    # ============================================
    
    SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Application secret key"
    )
    
    ALLOWED_ORIGINS: List[str] = Field(
        default=["*"],
        description="CORS allowed origins"
    )
    
    API_KEY_HEADER: str = Field(default="X-API-Key", description="API key header name")
    
    # ============================================
    # LLM PROVIDERS
    # ============================================
    
    LLM_PROVIDER: str = Field(default="openai", description="Default LLM provider")
    
    OPENAI_API_KEY: Optional[str] = Field(default=None, description="OpenAI API key")
    OPENAI_BASE_URL: str = Field(default="https://api.openai.com/v1", description="OpenAI base URL")
    
    ANTHROPIC_API_KEY: Optional[str] = Field(default=None, description="Anthropic API key")
    ANTHROPIC_BASE_URL: str = Field(default="https://api.anthropic.com/v1", description="Anthropic base URL")
    
    GOOGLE_API_KEY: Optional[str] = Field(default=None, description="Google API key")
    GOOGLE_BASE_URL: str = Field(default="https://generativelanguage.googleapis.com/v1", description="Google base URL")
    
    # ============================================
    # PRIVACY SETTINGS
    # ============================================
    
    PRIVACY_MODE: str = Field(default="strict", description="Privacy mode: strict, balanced, permissive")
    
    @field_validator("PRIVACY_MODE")
    @classmethod
    def validate_privacy_mode(cls, v: str) -> str:
        allowed = ["strict", "balanced", "permissive"]
        if v not in allowed:
            raise ValueError(f"PRIVACY_MODE must be one of: {allowed}")
        return v
    
    REDACT_ENTITIES: List[str] = Field(
        default=["PERSON", "EMAIL", "PHONE", "ADDRESS", "ID_NUMBER"],
        description="PII entity types to redact"
    )
    
    DP_ENABLED: bool = Field(default=True, description="Differential privacy enabled")
    DP_EPSILON: float = Field(default=1.0, ge=0.1, le=10.0, description="Differential privacy epsilon")
    
    # ============================================
    # DATABASE
    # ============================================
    
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://ghostproxy:securepassword@localhost:5432/ghostproxy",
        description="Database connection URL"
    )
    
    DB_POOL_SIZE: int = Field(default=5, ge=1, le=20, description="Database pool size")
    DB_MAX_OVERFLOW: int = Field(default=10, ge=0, le=50, description="Database max overflow")
    
    # ============================================
    # REDIS
    # ============================================
    
    REDIS_URL: str = Field(default="redis://localhost:6379/0", description="Redis connection URL")
    REDIS_PREFIX: str = Field(default="ghost_proxy:", description="Redis key prefix")
    
    # ============================================
    # RATE LIMITING
    # ============================================
    
    RATE_LIMIT_REQUESTS: int = Field(default=100, ge=1, description="Rate limit requests")
    RATE_LIMIT_WINDOW: int = Field(default=60, ge=1, description="Rate limit window (seconds)")
    
    # ============================================
    # LOGGING
    # ============================================
    
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    
    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of: {allowed}")
        return v
    
    LOG_ENCRYPTION_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Log encryption key (32 characters for AES-256)"
    )
    
    @field_validator("LOG_ENCRYPTION_KEY")
    @classmethod
    def validate_encryption_key(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("LOG_ENCRYPTION_KEY must be at least 32 characters")
        return v
    
    LOG_RETENTION_DAYS: int = Field(default=30, ge=1, le=365, description="Log retention days")
    LOG_PATH: str = Field(default="./logs", description="Log file path")
    ENCRYPTED_LOG_PATH: str = Field(default="./encrypted_logs", description="Encrypted log path")
    
    # ============================================
    # MONITORING
    # ============================================
    
    METRICS_ENABLED: bool = Field(default=True, description="Prometheus metrics enabled")
    METRICS_ENDPOINT: str = Field(default="/metrics", description="Metrics endpoint")
    
    # ============================================
    # AUDIT
    # ============================================
    
    AUDIT_ENABLED: bool = Field(default=True, description="Audit logging enabled")
    AUDIT_ENCRYPT: bool = Field(default=True, description="Encrypt audit logs")
    
    # ============================================
    # PERFORMANCE
    # ============================================
    
    MAX_REQUEST_SIZE: int = Field(default=1048576, description="Max request size (bytes)")
    REQUEST_TIMEOUT: int = Field(default=30, description="Request timeout (seconds)")
    MAX_RETRIES: int = Field(default=3, description="Max retries for failed requests")
    
    # ============================================
    # FEATURE FLAGS
    # ============================================
    
    FEATURE_OUTPUT_FILTERING: bool = Field(default=True, description="Filter LLM output")
    FEATURE_STYLESOMETRY_PROTECTION: bool = Field(default=True, description="Protect against stylometry")
    FEATURE_ADVERSARIAL_DETECTION: bool = Field(default=False, description="Detect adversarial inputs")

# ============================================
# CACHED SETTINGS INSTANCE
# ============================================

@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Returns:
        Settings: Application settings
    """
    return Settings()

# ============================================
# GLOBAL SETTINGS
# ============================================

settings = get_settings()