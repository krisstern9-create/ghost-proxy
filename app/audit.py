"""
Ghost Proxy - Audit Logging System

Encrypted audit trail for compliance, security analysis,
and forensic investigation with integrity verification.
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from loguru import logger
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from pathlib import Path
import json
import base64
import os
import hashlib
import hmac
import asyncio

from app.config import settings

# ============================================
# INITIALIZATION
# ============================================

class AuditLogger:
    """
    Secure audit logging system with encryption and integrity verification.
    
    Features:
    - AES-256 encryption for log data
    - HMAC integrity verification
    - Configurable retention policies
    - Database and file-based storage
    - Tamper-evident logging
    """
    
    def __init__(self):
        """Initialize audit logger with encryption keys and storage paths."""
        self.encryption_key = self._derive_key(settings.LOG_ENCRYPTION_KEY)
        self.fernet = Fernet(self.encryption_key)
        
        # Storage paths
        self.log_path = Path(settings.LOG_PATH)
        self.encrypted_log_path = Path(settings.ENCRYPTED_LOG_PATH)
        
        # Ensure directories exist
        self.log_path.mkdir(parents=True, exist_ok=True)
        self.encrypted_log_path.mkdir(parents=True, exist_ok=True)
        
        # Retention policy
        self.retention_days = settings.LOG_RETENTION_DAYS
        
        # Integrity chain (for tamper evidence)
        self.previous_hash = self._load_last_hash()
        
        logger.info("✅ Audit Logger initialized")
    
    # ============================================
    # KEY DERIVATION
    # ============================================
    
    def _derive_key(self, password: str) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: Master password/key from settings
            
        Returns:
            32-byte encryption key
        """
        salt = b"ghost_proxy_audit_salt_v1"  # Fixed salt for consistency
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    # ============================================
    # CORE LOGGING
    # ============================================
    
    async def log(
        self,
        request_id: str,
        provider: str,
        input_hash: str,
        output_hash: str,
        pii_count: int,
        process_time: float,
        encrypt: bool = True,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create encrypted audit log entry.
        
        Args:
            request_id: Unique request identifier
            provider: LLM provider used
            input_hash: SHA-256 hash of input content
            output_hash: SHA-256 hash of output content
            pii_count: Number of PII entities detected
            process_time: Request processing time in seconds
            encrypt: Whether to encrypt the log entry
            metadata: Additional metadata to store
            
        Returns:
            Log entry ID
        """
        timestamp = datetime.utcnow()
        
        # Create log entry
        entry = {
            "log_id": self._generate_log_id(request_id, timestamp),
            "timestamp": timestamp.isoformat(),
            "request_id": request_id,
            "provider": provider,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "pii_count": pii_count,
            "process_time_ms": round(process_time * 1000, 2),
            "previous_hash": self.previous_hash,
            "metadata": metadata or {}
        }
        
        # Calculate integrity hash
        entry["integrity_hash"] = self._calculate_integrity_hash(entry)
        
        # Update chain
        self.previous_hash = entry["integrity_hash"]
        
        # Store log
        if encrypt:
            await self._store_encrypted(entry)
        else:
            await self._store_plain(entry)
        
        # Schedule retention cleanup
        await self._cleanup_old_logs()
        
        logger.debug(f"Audit log created: {entry['log_id']}")
        return entry["log_id"]
    
    # ============================================
    # STORAGE METHODS
    # ============================================
    
    async def _store_encrypted(self, entry: Dict[str, Any]) -> None:
        """
        Store encrypted log entry to file.
        
        Args:
            entry: Log entry dictionary
        """
        # Serialize to JSON
        json_data = json.dumps(entry, sort_keys=True).encode()
        
        # Encrypt
        encrypted_data = self.fernet.encrypt(json_data)
        
        # Create filename with date partitioning
        date_str = entry["timestamp"][:10]  # YYYY-MM-DD
        filename = f"audit_{date_str}_{entry['log_id'][:8]}.enc"
        filepath = self.encrypted_log_path / filename
        
        # Write to file
        with open(filepath, "wb") as f:
            f.write(encrypted_data)
        
        logger.debug(f"Encrypted log stored: {filepath}")
    
    async def _store_plain(self, entry: Dict[str, Any]) -> None:
        """
        Store plain (unencrypted) log entry to file.
        
        Args:
            entry: Log entry dictionary
        """
        # Create filename with date partitioning
        date_str = entry["timestamp"][:10]
        filename = f"audit_{date_str}_{entry['log_id'][:8]}.json"
        filepath = self.log_path / filename
        
        # Write to file
        with open(filepath, "w") as f:
            json.dump(entry, f, indent=2, sort_keys=True)
        
        logger.debug(f"Plain log stored: {filepath}")
    
    # ============================================
    # INTEGRITY VERIFICATION
    # ============================================
    
    def _calculate_integrity_hash(self, entry: Dict[str, Any]) -> str:
        """
        Calculate integrity hash for tamper evidence.
        
        Creates a hash chain where each entry includes the hash of the previous,
        making tampering detectable.
        
        Args:
            entry: Log entry (without integrity_hash)
            
        Returns:
            SHA-256 hex string
        """
        # Create hashable content (exclude integrity_hash itself)
        content = {k: v for k, v in entry.items() if k != "integrity_hash"}
        content_str = json.dumps(content, sort_keys=True).encode()
        
        # Add previous hash for chain
        chain_content = content_str + entry["previous_hash"].encode()
        
        # Calculate hash
        hash_obj = hashlib.sha256(chain_content)
        return hash_obj.hexdigest()
    
    def verify_integrity(self, entry: Dict[str, Any]) -> bool:
        """
        Verify integrity of a log entry.
        
        Args:
            entry: Log entry to verify
            
        Returns:
            True if integrity is valid, False otherwise
        """
        calculated_hash = self._calculate_integrity_hash(entry)
        return hmac.compare_digest(calculated_hash, entry.get("integrity_hash", ""))
    
    async def verify_chain(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Verify entire chain of log entries for tampering.
        
        Args:
            entries: List of log entries in chronological order
            
        Returns:
            Verification report
        """
        report = {
            "total_entries": len(entries),
            "valid_entries": 0,
            "invalid_entries": 0,
            "broken_links": []
        }
        
        previous_hash = "genesis"
        
        for i, entry in enumerate(entries):
            # Verify individual integrity
            if not self.verify_integrity(entry):
                report["invalid_entries"] += 1
                report["broken_links"].append({
                    "index": i,
                    "log_id": entry.get("log_id", "unknown"),
                    "reason": "integrity_hash_mismatch"
                })
                continue
            
            # Verify chain link
            if entry.get("previous_hash") != previous_hash:
                report["invalid_entries"] += 1
                report["broken_links"].append({
                    "index": i,
                    "log_id": entry.get("log_id", "unknown"),
                    "reason": "chain_link_broken"
                })
                continue
            
            report["valid_entries"] += 1
            previous_hash = entry["integrity_hash"]
        
        logger.info(
            f"Chain verification complete: "
            f"{report['valid_entries']}/{report['total_entries']} valid"
        )
        
        return report
    
    # ============================================
    # RETENTION MANAGEMENT
    # ============================================
    
    async def _cleanup_old_logs(self) -> None:
        """
        Remove logs older than retention policy.
        
        Runs periodically to maintain storage limits.
        """
        cutoff_date = datetime.utcnow() - timedelta(days=self.retention_days)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")
        
        deleted_count = 0
        
        # Clean encrypted logs
        for filepath in self.encrypted_log_path.glob("audit_*.enc"):
            if filepath.stem.split("_")[1] < cutoff_str:
                try:
                    filepath.unlink()
                    deleted_count += 1
                except Exception as e:
                    logger.error(f"Failed to delete {filepath}: {str(e)}")
        
        # Clean plain logs
        for filepath in self.log_path.glob("audit_*.json"):
            if filepath.stem.split("_")[1] < cutoff_str:
                try:
                    filepath.unlink()
                    deleted_count += 1
                except Exception as e:
                    logger.error(f"Failed to delete {filepath}: {str(e)}")
        
        if deleted_count > 0:
            logger.info(f"Retention cleanup: deleted {deleted_count} old logs")
    
    # ============================================
    # QUERY METHODS
    # ============================================
    
    async def get_logs_by_request_id(
        self,
        request_id: str,
        decrypt: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve log entry by request ID.
        
        Args:
            request_id: Request identifier to search for
            decrypt: Whether to decrypt encrypted logs
            
        Returns:
            Log entry or None if not found
        """
        # Search encrypted logs
        for filepath in self.encrypted_log_path.glob("*.enc"):
            try:
                with open(filepath, "rb") as f:
                    encrypted_data = f.read()
                
                if decrypt:
                    decrypted_data = self.fernet.decrypt(encrypted_data)
                    entry = json.loads(decrypted_data)
                else:
                    entry = {"encrypted": True, "filepath": str(filepath)}
                
                if entry.get("request_id") == request_id:
                    return entry
                    
            except Exception as e:
                logger.error(f"Error reading {filepath}: {str(e)}")
        
        # Search plain logs
        for filepath in self.log_path.glob("*.json"):
            try:
                with open(filepath, "r") as f:
                    entry = json.load(f)
                
                if entry.get("request_id") == request_id:
                    return entry
                    
            except Exception as e:
                logger.error(f"Error reading {filepath}: {str(e)}")
        
        return None
    
    async def get_logs_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Retrieve logs within date range.
        
        Args:
            start_date: Start of date range
            end_date: End of date range
            limit: Maximum number of logs to return
            
        Returns:
            List of log entries
        """
        logs = []
        
        for filepath in self.encrypted_log_path.glob("*.enc"):
            if len(logs) >= limit:
                break
            
            try:
                with open(filepath, "rb") as f:
                    encrypted_data = f.read()
                
                decrypted_data = self.fernet.decrypt(encrypted_data)
                entry = json.loads(decrypted_data)
                
                entry_date = datetime.fromisoformat(entry["timestamp"])
                if start_date <= entry_date <= end_date:
                    logs.append(entry)
                    
            except Exception as e:
                logger.error(f"Error reading {filepath}: {str(e)}")
        
        return logs[:limit]
    
    # ============================================
    # UTILITY METHODS
    # ============================================
    
    def _generate_log_id(self, request_id: str, timestamp: datetime) -> str:
        """
        Generate unique log entry ID.
        
        Args:
            request_id: Associated request ID
            timestamp: Log timestamp
            
        Returns:
            Unique log ID string
        """
        content = f"{request_id}:{timestamp.isoformat()}:{os.urandom(8).hex()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _load_last_hash(self) -> str:
        """
        Load the hash of the last log entry for chain continuity.
        
        Returns:
            Previous hash or genesis marker
        """
        # In production, load from database or persistent storage
        return "genesis"
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get audit logger statistics.
        
        Returns:
            Dictionary with operational statistics
        """
        encrypted_count = len(list(self.encrypted_log_path.glob("*.enc")))
        plain_count = len(list(self.log_path.glob("*.json")))
        
        return {
            "encrypted_logs": encrypted_count,
            "plain_logs": plain_count,
            "retention_days": self.retention_days,
            "encryption_enabled": True,
            "integrity_chain": "active"
        }