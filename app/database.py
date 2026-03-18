"""
Ghost Proxy - Database Layer

Async SQLAlchemy with PostgreSQL for audit logs,
request tracking, and system metrics.
"""

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
    AsyncEngine
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import (
    Column,
    String,
    Integer,
    DateTime,
    Float,
    Boolean,
    Text,
    ForeignKey,
    Index,
    func,
    event
)
from sqlalchemy.sql import func as sql_func
from loguru import logger
from typing import Optional, List, AsyncGenerator
from datetime import datetime
import json

from app.config import settings

# ============================================
# DATABASE ENGINE SETUP
# ============================================

engine: Optional[AsyncEngine] = None
AsyncSessionLocal: Optional[async_sessionmaker] = None

def create_database_engine() -> AsyncEngine:
    """
    Create async database engine with connection pooling.
    
    Returns:
        AsyncEngine: SQLAlchemy async engine
    """
    global engine, AsyncSessionLocal
    
    if engine is not None:
        return engine
    
    logger.info(f"Creating database engine: {settings.DATABASE_URL[:30]}...")
    
    engine = create_async_engine(
        settings.DATABASE_URL,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_pre_ping=True,
        pool_recycle=3600,
        echo=settings.DEBUG,
        future=True
    )
    
    AsyncSessionLocal = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False
    )
    
    logger.info("✅ Database engine created")
    return engine

# ============================================
# BASE MODEL
# ============================================

class Base(DeclarativeBase):
    """Base class for all database models."""
    
    __abstract__ = True
    
    # Automatic timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=sql_func.now(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=sql_func.now(),
        onupdate=sql_func.now(),
        nullable=False
    )

# ============================================
# AUDIT LOG MODEL
# ============================================

class AuditLog(Base):
    """
    Encrypted audit log entry.
    
    Stores minimal metadata with encrypted payload
    for compliance and forensic analysis.
    """
    
    __tablename__ = "audit_logs"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    log_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    
    # Request metadata
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    output_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    
    # Privacy metrics
    pii_count: Mapped[int] = mapped_column(Integer, default=0)
    pii_redacted: Mapped[int] = mapped_column(Integer, default=0)
    
    # Performance metrics
    process_time_ms: Mapped[float] = mapped_column(Float, nullable=False)
    
    # Encrypted payload (actual log content)
    encrypted_payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Integrity verification
    integrity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    
    # Timestamps
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_audit_timestamp', 'timestamp'),
        Index('idx_audit_provider', 'provider'),
        Index('idx_audit_pii_count', 'pii_count'),
    )
    
    def __repr__(self) -> str:
        return f"<AuditLog(log_id={self.log_id}, request_id={self.request_id})>"

# ============================================
# REQUEST METRICS MODEL
# ============================================

class RequestMetric(Base):
    """
    Aggregated request metrics for monitoring.
    
    Time-series data for performance analysis and alerting.
    """
    
    __tablename__ = "request_metrics"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    
    # Time bucket (hourly aggregation)
    time_bucket: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    
    # Provider breakdown
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    
    # Counters
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    successful_requests: Mapped[int] = mapped_column(Integer, default=0)
    failed_requests: Mapped[int] = mapped_column(Integer, default=0)
    
    # PII statistics
    requests_with_pii: Mapped[int] = mapped_column(Integer, default=0)
    total_pii_detected: Mapped[int] = mapped_column(Integer, default=0)
    total_pii_redacted: Mapped[int] = mapped_column(Integer, default=0)
    
    # Performance statistics
    avg_process_time_ms: Mapped[float] = mapped_column(Float, default=0.0)
    min_process_time_ms: Mapped[float] = mapped_column(Float, default=0.0)
    max_process_time_ms: Mapped[float] = mapped_column(Float, default=0.0)
    p95_process_time_ms: Mapped[float] = mapped_column(Float, default=0.0)
    
    # Privacy mode distribution
    strict_mode_requests: Mapped[int] = mapped_column(Integer, default=0)
    balanced_mode_requests: Mapped[int] = mapped_column(Integer, default=0)
    permissive_mode_requests: Mapped[int] = mapped_column(Integer, default=0)
    
    __table_args__ = (
        Index('idx_metric_bucket_provider', 'time_bucket', 'provider'),
    )
    
    def __repr__(self) -> str:
        return f"<RequestMetric(bucket={self.time_bucket}, provider={self.provider})>"

# ============================================
# SECURITY EVENT MODEL
# ============================================

class SecurityEvent(Base):
    """
    Security-related events for threat detection.
    
    Tracks potential attacks, policy violations, and anomalies.
    """
    
    __tablename__ = "security_events"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    
    # Event identification
    event_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    
    # Severity level (1-5: low to critical)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    
    # Event details
    request_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # IPv6 compatible
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Event data
    description: Mapped[str] = mapped_column(Text, nullable=False)
    metadata: Mapped[Optional[dict]] = mapped_column(nullable=True)  # JSON column
    
    # Response actions
    action_taken: Mapped[str] = mapped_column(String(100), nullable=False)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Timestamp
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    
    __table_args__ = (
        Index('idx_security_event_type', 'event_type'),
        Index('idx_security_severity', 'severity'),
    )
    
    def __repr__(self) -> str:
        return f"<SecurityEvent(event_id={self.event_id}, type={self.event_type})>"

# ============================================
# DATABASE OPERATIONS
# ============================================

async def init_db() -> None:
    """
    Initialize database schema.
    
    Creates all tables if they don't exist.
    In production, use Alembic migrations instead.
    """
    global engine
    
    if engine is None:
        create_database_engine()
    
    logger.info("Initializing database schema...")
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    logger.info("✅ Database schema initialized")

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session dependency.
    
    Yields:
        AsyncSession: Database session
    """
    if AsyncSessionLocal is None:
        create_database_engine()
    
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def close_db() -> None:
    """
    Close database connections.
    """
    global engine
    
    if engine is not None:
        await engine.dispose()
        engine = None
        logger.info("✅ Database connections closed")

# ============================================
# REPOSITORY CLASSES
# ============================================

class AuditLogRepository:
    """Repository for audit log operations."""
    
    @staticmethod
    async def create(
        session: AsyncSession,
        log_id: str,
        request_id: str,
        provider: str,
        input_hash: str,
        output_hash: str,
        pii_count: int,
        pii_redacted: int,
        process_time_ms: float,
        encrypted_payload: Optional[str],
        integrity_hash: str,
        previous_hash: str,
        timestamp: datetime
    ) -> AuditLog:
        """Create new audit log entry."""
        log_entry = AuditLog(
            log_id=log_id,
            request_id=request_id,
            provider=provider,
            input_hash=input_hash,
            output_hash=output_hash,
            pii_count=pii_count,
            pii_redacted=pii_redacted,
            process_time_ms=process_time_ms,
            encrypted_payload=encrypted_payload,
            integrity_hash=integrity_hash,
            previous_hash=previous_hash,
            timestamp=timestamp
        )
        
        session.add(log_entry)
        await session.commit()
        await session.refresh(log_entry)
        
        return log_entry
    
    @staticmethod
    async def get_by_request_id(
        session: AsyncSession,
        request_id: str
    ) -> Optional[AuditLog]:
        """Get audit log by request ID."""
        result = await session.execute(
            AuditLog.select().where(AuditLog.request_id == request_id)
        )
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_by_date_range(
        session: AsyncSession,
        start_date: datetime,
        end_date: datetime,
        limit: int = 100
    ) -> List[AuditLog]:
        """Get audit logs within date range."""
        result = await session.execute(
            AuditLog.select()
            .where(AuditLog.timestamp.between(start_date, end_date))
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
        )
        return result.scalars().all()

class SecurityEventRepository:
    """Repository for security event operations."""
    
    @staticmethod
    async def create(
        session: AsyncSession,
        event_id: str,
        event_type: str,
        severity: int,
        description: str,
        action_taken: str,
        request_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        blocked: bool = False,
        metadata: Optional[dict] = None
    ) -> SecurityEvent:
        """Create new security event."""
        event = SecurityEvent(
            event_id=event_id,
            event_type=event_type,
            severity=severity,
            request_id=request_id,
            source_ip=source_ip,
            description=description,
            metadata=metadata,
            action_taken=action_taken,
            blocked=blocked,
            timestamp=datetime.utcnow()
        )
        
        session.add(event)
        await session.commit()
        await session.refresh(event)
        
        return event

# ============================================
# EVENT LISTENERS
# ============================================

@event.listens_for(AuditLog, "before_insert")
def receive_before_insert(mapper, connection, target):
    """Log before audit log insertion."""
    logger.debug(f"Creating audit log: {target.log_id}")

@event.listens_for(SecurityEvent, "before_insert")
def receive_security_event_insert(mapper, connection, target):
    """Log before security event insertion."""
    logger.warning(
        f"Security event: {target.event_type} "
        f"(severity={target.severity}, blocked={target.blocked})"
    )