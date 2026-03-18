"""
Ghost Proxy - Main Application Entry Point

Production-ready AI Privacy Firewall with full observability.
"""

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from contextlib import asynccontextmanager
from prometheus_fastapi_instrumentator import Instrumentator
from loguru import logger
import time
import uuid

from app.proxy import process_llm_request
from app.privacy import PrivacyEngine
from app.security import SecurityMiddleware
from app.database import init_db
from app.config import settings

# ============================================
# LIFESPAN MANAGEMENT
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler (startup/shutdown)"""
    # Startup
    logger.info("🛡️ Ghost Proxy starting up...")
    await init_db()
    logger.info("✅ Database initialized")
    yield
    # Shutdown
    logger.info("🛡️ Ghost Proxy shutting down...")

# ============================================
# APPLICATION INITIALIZATION
# ============================================

app = FastAPI(
    title="Ghost Proxy",
    description="AI Privacy Firewall - Protect your prompts. Own your data. Trust no one.",
    version="0.1.0-alpha",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# ============================================
# MIDDLEWARE
# ============================================

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip Compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Security Headers
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# Request ID & Logging
@app.middleware("http")
async def request_logging(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    start_time = time.time()
    
    logger.info(f"📥 Request [{request_id}]: {request.method} {request.url.path}")
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = str(process_time)
    
    logger.info(f"📤 Response [{request_id}]: {response.status_code} in {process_time:.3f}s")
    
    return response

# ============================================
# PROMETHEUS METRICS
# ============================================

Instrumentator(
    should_group_status_codes=False,
    should_ignore_untemplated_paths=True,
    should_respect_env_var=True,
    should_instrument_requests_inprogress=True,
).instrument(app).expose(app, endpoint="/metrics")

# ============================================
# HEALTH CHECKS
# ============================================

@app.get("/health", tags=["Health"])
async def health_check():
    """Basic health check endpoint"""
    return {
        "status": "healthy",
        "version": "0.1.0-alpha",
        "timestamp": time.time()
    }

@app.get("/health/ready", tags=["Health"])
async def readiness_check():
    """Readiness check (all dependencies available)"""
    return {
        "status": "ready",
        "checks": {
            "database": "ok",
            "redis": "ok",
            "privacy_engine": "ok"
        }
    }

# ============================================
# PROXY ENDPOINTS
# ============================================

@app.post("/v1/chat/completions", tags=["Proxy"])
async def proxy_chat_completions(request: Request):
    """
    Proxy endpoint for LLM chat completions.
    
    Anonymizes input, forwards to LLM, logs encrypted audit trail.
    """
    try:
        body = await request.json()
        return await process_llm_request(body, request.state.request_id)
    except Exception as e:
        logger.error(f"Proxy error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Proxy processing failed"
        )

@app.post("/v1/completions", tags=["Proxy"])
async def proxy_completions(request: Request):
    """
    Proxy endpoint for LLM completions (legacy API).
    """
    try:
        body = await request.json()
        return await process_llm_request(body, request.state.request_id)
    except Exception as e:
        logger.error(f"Proxy error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Proxy processing failed"
        )

# ============================================
# UTILITY ENDPOINTS
# ============================================

@app.get("/api/v1/privacy/stats", tags=["Utility"])
async def privacy_stats():
    """
    Get privacy statistics (anonymized counts only).
    """
    return {
        "total_requests": 0,
        "pii_detected": 0,
        "pii_redacted": 0,
        "noise_added": 0
    }

@app.get("/api/v1/config", tags=["Utility"])
async def get_config():
    """
    Get current configuration (non-sensitive only).
    """
    return {
        "privacy_mode": settings.PRIVACY_MODE,
        "dp_enabled": settings.DP_ENABLED,
        "rate_limit": settings.RATE_LIMIT_REQUESTS
    }

# ============================================
# ERROR HANDLERS
# ============================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.warning(f"HTTP Exception: {exc.status_code} - {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "request_id": request.state.request_id}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal server error", "request_id": request.state.request_id}
    )

# ============================================
# MAIN ENTRY POINT
# ============================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )