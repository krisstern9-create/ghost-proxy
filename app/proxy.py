"""
Ghost Proxy - Core Proxy Logic

Handles LLM request processing with privacy preservation,
multi-provider support, and encrypted audit logging.
"""

from fastapi import HTTPException, status
from loguru import logger
import httpx
import time
import json
from typing import Dict, Any, Optional
from datetime import datetime

from app.config import settings
from app.privacy import PrivacyEngine
from app.audit import AuditLogger

# ============================================
# INITIALIZATION
# ============================================

privacy_engine = PrivacyEngine()
audit_logger = AuditLogger()

# ============================================
# LLM PROVIDER CONFIGURATION
# ============================================

PROVIDER_CONFIGS = {
    "openai": {
        "base_url": settings.OPENAI_BASE_URL,
        "api_key": settings.OPENAI_API_KEY,
        "header_name": "Authorization",
        "header_prefix": "Bearer "
    },
    "anthropic": {
        "base_url": settings.ANTHROPIC_BASE_URL,
        "api_key": settings.ANTHROPIC_API_KEY,
        "header_name": "x-api-key",
        "header_prefix": ""
    },
    "google": {
        "base_url": settings.GOOGLE_BASE_URL,
        "api_key": settings.GOOGLE_API_KEY,
        "header_name": "Authorization",
        "header_prefix": "Bearer "
    }
}

# ============================================
# CORE PROXY FUNCTION
# ============================================

async def process_llm_request(
    body: Dict[str, Any],
    request_id: str,
    provider: Optional[str] = None
) -> Dict[str, Any]:
    """
    Process LLM request with privacy preservation.
    
    Flow:
    1. Detect and redact PII from input
    2. Add differential privacy noise (if enabled)
    3. Forward to LLM provider
    4. Process response
    5. Log encrypted audit trail
    
    Args:
        body: Request body from client
        request_id: Unique request identifier
        provider: LLM provider (auto-detect if None)
    
    Returns:
        LLM response with privacy metadata
    """
    start_time = time.time()
    
    # ============================================
    # STEP 1: DETERMINE PROVIDER
    # ============================================
    
    if provider is None:
        provider = settings.LLM_PROVIDER
    
    if provider not in PROVIDER_CONFIGS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown provider: {provider}"
        )
    
    provider_config = PROVIDER_CONFIGS[provider]
    
    if not provider_config["api_key"]:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Provider {provider} not configured"
        )
    
    # ============================================
    # STEP 2: PRIVACY PROCESSING
    # ============================================
    
    logger.info(f"[{request_id}] Starting privacy processing...")
    
    # Extract messages/content from request
    original_content = extract_content_from_request(body)
    
    # Analyze for PII
    pii_analysis = privacy_engine.analyze(original_content)
    
    # Redact PII based on privacy mode
    redacted_content = privacy_engine.redact(
        original_content,
        pii_analysis,
        mode=settings.PRIVACY_MODE
    )
    
    # Add differential privacy noise (if enabled)
    if settings.DP_ENABLED:
        noisy_content = privacy_engine.add_noise(
            redacted_content,
            epsilon=settings.DP_EPSILON
        )
    else:
        noisy_content = redacted_content
    
    # Replace content in request body
    anonymized_body = replace_content_in_request(body, noisy_content)
    
    logger.info(
        f"[{request_id}] Privacy processing complete: "
        f"{len(pii_analysis)} entities detected, "
        f"{len([e for e in pii_analysis if e['redacted']])} redacted"
    )
    
    # ============================================
    # STEP 3: FORWARD TO LLM PROVIDER
    # ============================================
    
    logger.info(f"[{request_id}] Forwarding to {provider}...")
    
    try:
        response = await forward_to_provider(
            provider=provider,
            config=provider_config,
            body=anonymized_body,
            request_id=request_id
        )
    except httpx.TimeoutException as e:
        logger.error(f"[{request_id}] Provider timeout: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="LLM provider timeout"
        )
    except httpx.HTTPError as e:
        logger.error(f"[{request_id}] Provider error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM provider error: {str(e)}"
        )
    
    # ============================================
    # STEP 4: PROCESS RESPONSE
    # ============================================
    
    process_time = time.time() - start_time
    
    # Extract response content
    response_content = extract_content_from_response(response)
    
    # Optional: Filter output for safety
    if settings.FEATURE_OUTPUT_FILTERING:
        filtered_content = privacy_engine.filter_output(response_content)
        response = replace_content_in_response(response, filtered_content)
    
    # Add privacy metadata to response
    response["ghost_proxy"] = {
        "request_id": request_id,
        "provider": provider,
        "privacy_mode": settings.PRIVACY_MODE,
        "pii_detected": len(pii_analysis),
        "pii_redacted": len([e for e in pii_analysis if e['redacted']]),
        "noise_added": settings.DP_ENABLED,
        "process_time_ms": round(process_time * 1000, 2),
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # ============================================
    # STEP 5: AUDIT LOGGING
    # ============================================
    
    if settings.AUDIT_ENABLED:
        await audit_logger.log(
            request_id=request_id,
            provider=provider,
            input_hash=hash_content(original_content),
            output_hash=hash_content(response_content),
            pii_count=len(pii_analysis),
            process_time=process_time,
            encrypt=settings.AUDIT_ENCRYPT
        )
    
    logger.info(f"[{request_id}] Request complete in {process_time:.3f}s")
    
    return response

# ============================================
# HELPER FUNCTIONS
# ============================================

def extract_content_from_request(body: Dict[str, Any]) -> str:
    """
    Extract text content from LLM request body.
    
    Handles different API formats (OpenAI, Anthropic, Google).
    """
    if "messages" in body:
        # OpenAI format
        return " ".join([m.get("content", "") for m in body["messages"]])
    elif "prompt" in body:
        # Legacy/completions format
        return body["prompt"]
    elif "contents" in body:
        # Google format
        return " ".join([p.get("text", "") for p in body["contents"]])
    else:
        return str(body)

def replace_content_in_request(
    body: Dict[str, Any],
    new_content: str
) -> Dict[str, Any]:
    """
    Replace content in request body with anonymized version.
    """
    modified = body.copy()
    
    if "messages" in modified:
        modified["messages"] = [
            {**m, "content": new_content} if i == len(modified["messages"]) - 1 else m
            for i, m in enumerate(modified["messages"])
        ]
    elif "prompt" in modified:
        modified["prompt"] = new_content
    elif "contents" in modified:
        modified["contents"] = [{"parts": [{"text": new_content}]}]
    
    return modified

def extract_content_from_response(response: Dict[str, Any]) -> str:
    """
    Extract text content from LLM response.
    """
    if "choices" in response:
        # OpenAI format
        return response["choices"][0].get("message", {}).get("content", "")
    elif "content" in response:
        # Anthropic format
        return response["content"][0].get("text", "")
    elif "candidates" in response:
        # Google format
        return response["candidates"][0].get("content", {}).get("parts", [{}])[0].get("text", "")
    else:
        return str(response)

def replace_content_in_response(
    response: Dict[str, Any],
    new_content: str
) -> Dict[str, Any]:
    """
    Replace content in response body with filtered version.
    """
    modified = response.copy()
    
    if "choices" in modified:
        modified["choices"][0]["message"]["content"] = new_content
    elif "content" in modified:
        modified["content"][0]["text"] = new_content
    elif "candidates" in modified:
        modified["candidates"][0]["content"]["parts"][0]["text"] = new_content
    
    return modified

async def forward_to_provider(
    provider: str,
    config: Dict[str, Any],
    body: Dict[str, Any],
    request_id: str
) -> Dict[str, Any]:
    """
    Forward request to LLM provider with proper headers and retry logic.
    """
    url = f"{config['base_url']}/chat/completions"
    
    headers = {
        "Content-Type": "application/json",
        config["header_name"]: f"{config['header_prefix']}{config['api_key']}"
    }
    
    # Add provider-specific headers
    if provider == "anthropic":
        headers["anthropic-version"] = "2023-06-01"
    
    async with httpx.AsyncClient(
        timeout=settings.REQUEST_TIMEOUT,
        follow_redirects=True
    ) as client:
        for attempt in range(settings.MAX_RETRIES):
            try:
                response = await client.post(url, headers=headers, json=body)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                if attempt == settings.MAX_RETRIES - 1:
                    raise
                logger.warning(f"[{request_id}] Retry {attempt + 1}/{settings.MAX_RETRIES}")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff

def hash_content(content: str) -> str:
    """
    Create SHA-256 hash of content for audit logging.
    """
    import hashlib
    return hashlib.sha256(content.encode()).hexdigest()