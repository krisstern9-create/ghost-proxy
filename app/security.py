"""
Ghost Proxy - Security Middleware

Rate limiting, request validation, API key authentication,
and attack detection/protection.
"""

from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from loguru import logger
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import hashlib
import hmac
import re
import asyncio
import redis.asyncio as redis

from app.config import settings

# ============================================
# INITIALIZATION
# ============================================

# Rate limiter setup
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.REDIS_URL,
    default_limits=[f"{settings.RATE_LIMIT_REQUESTS}/{settings.RATE_LIMIT_WINDOW}s"]
)

# HTTP Bearer for API key auth
security = HTTPBearer(auto_error=False)

# Redis for advanced rate limiting
redis_client: Optional[redis.Redis] = None

# ============================================
# SECURITY MIDDLEWARE CLASS
# ============================================

class SecurityMiddleware:
    """
    Security middleware for request validation and protection.
    
    Features:
    - API key authentication
    - Rate limiting (sliding window)
    - Request size validation
    - SQL injection detection
    - XSS prevention
    - Request fingerprinting
    """
    
    def __init__(self):
        """Initialize security components."""
        self.api_keys = self._load_api_keys()
        self.blocked_ips = set()
        self.request_cache = {}
        
        # Attack detection patterns
        self.sql_injection_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)",
            r"(--|;|'|\"|`)",
            r"(\b(OR|AND)\b\s+\d+\s*=\s*\d+)",
        ]
        
        self.xss_patterns = [
            r"(<script|javascript:|on\w+\s*=)",
            r"(alert\(|confirm\(|prompt\()",
        ]
        
        logger.info("✅ Security Middleware initialized")
    
    def _load_api_keys(self) -> Dict[str, Dict[str, Any]]:
        """
        Load API keys from configuration.
        
        In production, load from database or secrets manager.
        """
        # For now, generate a default key
        default_key = hashlib.sha256(settings.SECRET_KEY.encode()).hexdigest()
        
        return {
            default_key: {
                "name": "default",
                "created_at": datetime.utcnow(),
                "rate_limit": settings.RATE_LIMIT_REQUESTS,
                "enabled": True
            }
        }
    
    async def validate_request(
        self,
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = None
    ) -> Dict[str, Any]:
        """
        Validate incoming request for security.
        
        Args:
            request: FastAPI request object
            credentials: Optional HTTP bearer credentials
            
        Returns:
            Validation result with metadata
            
        Raises:
            HTTPException: If validation fails
        """
        # 1. API Key Authentication
        api_key_info = await self._validate_api_key(credentials)
        
        # 2. IP Blocking Check
        client_ip = self._get_client_ip(request)
        if client_ip in self.blocked_ips:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="IP address blocked"
            )
        
        # 3. Request Size Validation
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > settings.MAX_REQUEST_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Request too large (max {settings.MAX_REQUEST_SIZE} bytes)"
            )
        
        # 4. Content Validation (if body present)
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()
            if body:
                await self._validate_content(body)
        
        # 5. Request Fingerprinting
        fingerprint = await self._create_fingerprint(request)
        
        # 6. Anomaly Detection
        await self._detect_anomalies(request, fingerprint)
        
        return {
            "api_key": api_key_info,
            "client_ip": client_ip,
            "fingerprint": fingerprint,
            "timestamp": datetime.utcnow()
        }
    
    async def _validate_api_key(
        self,
        credentials: Optional[HTTPAuthorizationCredentials]
    ) -> Optional[Dict[str, Any]]:
        """
        Validate API key from request.
        
        Args:
            credentials: HTTP bearer credentials
            
        Returns:
            API key metadata or None
            
        Raises:
            HTTPException: If API key is invalid or missing
        """
        if not credentials:
            # Allow requests without API key in development
            if settings.DEBUG:
                logger.warning("No API key provided (debug mode)")
                return None
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key required",
                    headers={"WWW-Authenticate": "Bearer"}
                )
        
        # Hash the provided key for comparison
        key_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        
        if key_hash not in self.api_keys:
            logger.warning(f"Invalid API key attempt: {key_hash[:8]}...")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        api_key_info = self.api_keys[key_hash]
        
        if not api_key_info.get("enabled", True):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key disabled"
            )
        
        logger.debug(f"API key validated: {api_key_info['name']}")
        return api_key_info
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Extract client IP address from request.
        
        Handles X-Forwarded-For and X-Real-IP headers.
        """
        # Check for proxy headers
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
        
        # Fallback to direct connection
        if request.client:
            return request.client.host
        
        return "unknown"
    
    async def _validate_content(self, body: bytes) -> None:
        """
        Validate request content for attacks.
        
        Args:
            body: Request body bytes
            
        Raises:
            HTTPException: If malicious content detected
        """
        try:
            content = body.decode("utf-8")
        except UnicodeDecodeError:
            # Non-UTF8 content might be an attack
            logger.warning("Non-UTF8 content detected")
            return  # Allow binary content
        
        # Check for SQL injection
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                logger.warning(f"SQL injection pattern detected: {pattern}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid request content"
                )
        
        # Check for XSS
        for pattern in self.xss_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                logger.warning(f"XSS pattern detected: {pattern}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid request content"
                )
    
    async def _create_fingerprint(self, request: Request) -> str:
        """
        Create unique fingerprint for request.
        
        Used for rate limiting and anomaly detection.
        """
        components = [
            self._get_client_ip(request),
            request.headers.get("user-agent", ""),
            request.headers.get("accept-language", ""),
            request.url.path
        ]
        
        fingerprint_data = "|".join(components)
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    async def _detect_anomalies(
        self,
        request: Request,
        fingerprint: str
    ) -> None:
        """
        Detect anomalous request patterns.
        
        Args:
            request: FastAPI request
            fingerprint: Request fingerprint
            
        Raises:
            HTTPException: If anomaly threshold exceeded
        """
        # Initialize Redis if not already done
        global redis_client
        if redis_client is None:
            redis_client = redis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
        
        # Track request frequency per fingerprint
        key = f"ghost_proxy:fingerprint:{fingerprint}"
        count = await redis_client.incr(key)
        
        if count == 1:
            await redis_client.expire(key, 60)  # 1 minute window
        
        # Check for burst attacks
        if count > settings.RATE_LIMIT_REQUESTS * 2:
            logger.warning(f"Burst attack detected: {fingerprint[:8]}...")
            
            # Block IP temporarily
            client_ip = self._get_client_ip(request)
            self.blocked_ips.add(client_ip)
            
            # Schedule unblock after 5 minutes
            asyncio.create_task(self._unblock_ip(client_ip, 300))
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests - IP blocked"
            )
    
    async def _unblock_ip(self, ip: str, delay: int) -> None:
        """
        Unblock IP after delay.
        
        Args:
            ip: IP address to unblock
            delay: Delay in seconds
        """
        await asyncio.sleep(delay)
        self.blocked_ips.discard(ip)
        logger.info(f"IP unblocked: {ip}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get security middleware statistics.
        
        Returns:
            Dictionary with operational statistics
        """
        return {
            "blocked_ips": len(self.blocked_ips),
            "api_keys_loaded": len(self.api_keys),
            "rate_limit": f"{settings.RATE_LIMIT_REQUESTS}/{settings.RATE_LIMIT_WINDOW}s",
            "max_request_size": settings.MAX_REQUEST_SIZE
        }

# ============================================
# DECORATORS
# ============================================

def require_api_key(func):
    """
    Decorator to require valid API key.
    
    Usage:
        @app.get("/protected")
        @require_api_key
        async def protected_endpoint():
            ...
    """
    from functools import wraps
    
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        security_middleware = SecurityMiddleware()
        credentials = await security(request)
        
        await security_middleware.validate_request(request, credentials)
        
        return await func(request, *args, **kwargs)
    
    return wrapper

# ============================================
# UTILITY FUNCTIONS
# ============================================

def generate_api_key() -> str:
    """
    Generate new API key.
    
    Returns:
        Secure API key string
    """
    import secrets
    return secrets.token_urlsafe(32)

def hash_api_key(api_key: str) -> str:
    """
    Hash API key for storage.
    
    Args:
        api_key: Plain text API key
        
    Returns:
        SHA-256 hash
    """
    return hashlib.sha256(api_key.encode()).hexdigest()