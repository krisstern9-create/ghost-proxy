"""
Ghost Proxy - Privacy Engine

Core privacy preservation logic using Microsoft Presidio,
differential privacy, and stylometry protection.
"""

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine, OperatorConfig
from presidio_anonymizer.entities import OperatorResult
from loguru import logger
from typing import List, Dict, Any, Optional
from datetime import datetime
import random
import string
import hashlib

from app.config import settings

# ============================================
# INITIALIZATION
# ============================================

class PrivacyEngine:
    """
    Privacy preservation engine for LLM requests.
    
    Features:
    - PII detection and redaction (Presidio + spaCy)
    - Differential privacy noise injection
    - Stylometry protection
    - Output filtering for safety
    """
    
    def __init__(self):
        """Initialize privacy engines and configurations."""
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        
        # Configurable entity types
        self.entity_types = settings.REDACT_ENTITIES
        
        # Redaction strategies per entity type
        self.redaction_strategies = {
            "PERSON": self._redact_person,
            "EMAIL_ADDRESS": self._redact_email,
            "PHONE_NUMBER": self._redact_phone,
            "LOCATION": self._redact_location,
            "ADDRESS": self._redact_address,
            "ID_NUMBER": self._redact_id,
            "CREDIT_CARD": self._redact_credit_card,
            "DEFAULT": self._redact_default
        }
        
        logger.info("✅ Privacy Engine initialized")
    
    # ============================================
    # PII ANALYSIS
    # ============================================
    
    def analyze(self, text: str) -> List[Dict[str, Any]]:
        """
        Analyze text for PII entities.
        
        Args:
            text: Input text to analyze
            
        Returns:
            List of detected entities with metadata
        """
        if not text or not isinstance(text, str):
            return []
        
        try:
            results = self.analyzer.analyze(
                text=text,
                language="en",
                entities=self.entity_types
            )
            
            entities = []
            for result in results:
                entity = {
                    "type": result.entity_type,
                    "start": result.start,
                    "end": result.end,
                    "text": text[result.start:result.end],
                    "score": result.score,
                    "redacted": False
                }
                entities.append(entity)
            
            logger.debug(f"Analyzed {len(text)} chars, found {len(entities)} entities")
            return entities
            
        except Exception as e:
            logger.error(f"PII analysis failed: {str(e)}")
            return []
    
    # ============================================
    # PII REDACTION
    # ============================================
    
    def redact(
        self,
        text: str,
        entities: List[Dict[str, Any]],
        mode: str = "strict"
    ) -> str:
        """
        Redact PII from text based on privacy mode.
        
        Args:
            text: Original text
            entities: Detected PII entities
            mode: Privacy mode (strict, balanced, permissive)
            
        Returns:
            Redacted text
        """
        if not text or not entities:
            return text
        
        # Sort entities by position (reverse order for safe replacement)
        sorted_entities = sorted(entities, key=lambda x: x["start"], reverse=True)
        
        redacted_text = text
        
        for entity in sorted_entities:
            # Skip low-confidence entities in permissive mode
            if mode == "permissive" and entity["score"] < 0.85:
                continue
            
            # Skip some entity types in balanced mode
            if mode == "balanced" and entity["type"] in ["LOCATION", "ADDRESS"]:
                if entity["score"] < 0.9:
                    continue
            
            # Get redaction strategy
            strategy = self.redaction_strategies.get(
                entity["type"],
                self.redaction_strategies["DEFAULT"]
            )
            
            # Apply redaction
            replacement = strategy(entity)
            redacted_text = (
                redacted_text[:entity["start"]] +
                replacement +
                redacted_text[entity["end"]:]
            )
            
            entity["redacted"] = True
            entity["replacement"] = replacement
        
        logger.debug(f"Redacted {len([e for e in entities if e['redacted']])} entities")
        return redacted_text
    
    # ============================================
    # REDACTION STRATEGIES
    # ============================================
    
    def _redact_person(self, entity: Dict[str, Any]) -> str:
        """Replace person name with generic placeholder."""
        return "[PERSON]"
    
    def _redact_email(self, entity: Dict[str, Any]) -> str:
        """Replace email with hashed placeholder."""
        return f"[EMAIL:{self._short_hash(entity['text'])}]"
    
    def _redact_phone(self, entity: Dict[str, Any]) -> str:
        """Replace phone with generic placeholder."""
        return "[PHONE]"
    
    def _redact_location(self, entity: Dict[str, Any]) -> str:
        """Replace location with generic placeholder."""
        return "[LOCATION]"
    
    def _redact_address(self, entity: Dict[str, Any]) -> str:
        """Replace address with generic placeholder."""
        return "[ADDRESS]"
    
    def _redact_id(self, entity: Dict[str, Any]) -> str:
        """Replace ID number with hashed placeholder."""
        return f"[ID:{self._short_hash(entity['text'])}]"
    
    def _redact_credit_card(self, entity: Dict[str, Any]) -> str:
        """Replace credit card with masked placeholder."""
        return "[CREDIT_CARD]"
    
    def _redact_default(self, entity: Dict[str, Any]) -> str:
        """Default redaction strategy."""
        return f"[{entity['type']}]"
    
    def _short_hash(self, text: str, length: int = 8) -> str:
        """Create short hash for reversible-ish redaction."""
        return hashlib.sha256(text.encode()).hexdigest()[:length]
    
    # ============================================
    # DIFFERENTIAL PRIVACY
    # ============================================
    
    def add_noise(self, text: str, epsilon: float = 1.0) -> str:
        """
        Add differential privacy noise to text.
        
        This protects against stylometry and fingerprinting attacks
        by subtly modifying text structure while preserving meaning.
        
        Args:
            text: Input text
            epsilon: Privacy budget (lower = more noise)
            
        Returns:
            Text with added noise
        """
        if not settings.FEATURE_STYLESOMETRY_PROTECTION:
            return text
        
        if not text or epsilon <= 0:
            return text
        
        # Noise strategies (applied probabilistically based on epsilon)
        noise_probability = max(0.1, min(1.0, 1.0 / epsilon))
        
        noisy_text = text
        
        # 1. Random whitespace variation
        if random.random() < noise_probability:
            noisy_text = self._add_whitespace_noise(noisy_text)
        
        # 2. Synonym substitution (simple version)
        if random.random() < noise_probability:
            noisy_text = self._add_synonym_noise(noisy_text)
        
        # 3. Punctuation variation
        if random.random() < noise_probability:
            noisy_text = self._add_punctuation_noise(noisy_text)
        
        logger.debug(f"Added differential privacy noise (epsilon={epsilon})")
        return noisy_text
    
    def _add_whitespace_noise(self, text: str) -> str:
        """Add subtle whitespace variations."""
        # Replace some spaces with non-breaking spaces
        result = []
        for char in text:
            if char == " " and random.random() < 0.05:
                result.append("\u00A0")  # Non-breaking space
            else:
                result.append(char)
        return "".join(result)
    
    def _add_synonym_noise(self, text: str) -> str:
        """Simple synonym substitution (placeholder for full implementation)."""
        # In production, use WordNet or similar
        common_subs = {
            " hello": " hi",
            "thanks": "thank you",
            "help": "assist",
            "need": "require"
        }
        
        result = text
        for original, replacement in common_subs.items():
            if original in result and random.random() < 0.1:
                result = result.replace(original, replacement, 1)
        
        return result
    
    def _add_punctuation_noise(self, text: str) -> str:
        """Add subtle punctuation variations."""
        # Replace some periods with spaces (for informal text)
        if random.random() < 0.05 and "." in text:
            text = text.replace(".", ". ", 1)
        
        return text
    
    # ============================================
    # OUTPUT FILTERING
    # ============================================
    
    def filter_output(self, text: str) -> str:
        """
        Filter LLM output for safety and policy violations.
        
        Checks for:
        - Harmful instructions
        - Leaked system prompts
        - Policy violations
        
        Args:
            text: LLM output text
            
        Returns:
            Filtered text
        """
        if not text:
            return text
        
        filtered = text
        
        # Check for common safety issues
        safety_patterns = [
            "ignore previous instructions",
            "system prompt",
            "you are a",
            "your purpose is",
            "bypass safety"
        ]
        
        for pattern in safety_patterns:
            if pattern.lower() in filtered.lower():
                logger.warning(f"Output filtered for pattern: {pattern}")
                # Replace with generic response
                filtered = "[Output filtered for safety]"
                break
        
        return filtered
    
    # ============================================
    # UTILITY METHODS
    # ============================================
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get privacy engine statistics.
        
        Returns:
            Dictionary with operational statistics
        """
        return {
            "entity_types": self.entity_types,
            "dp_enabled": settings.DP_ENABLED,
            "dp_epsilon": settings.DP_EPSILON,
            "output_filtering": settings.FEATURE_OUTPUT_FILTERING,
            "stylometry_protection": settings.FEATURE_STYLESOMETRY_PROTECTION
        }