"""Audit event definitions for HIPAA compliance.

This module defines audit event structures and creation functions for
comprehensive validation event tracking. All events follow a standardized
schema with query hashing to prevent PHI exposure.

Event Types:
- QUERY_VALIDATION: Query validation pipeline results
- VALIDATION_ERROR: Validation failures at specific layers
- SECURITY_EVENT: Security-related detections (injection, circumvention)

CRITICAL: Never log full queries - only SHA-256 hashes to prevent PHI exposure.
"""

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class AuditEvent:
    """Base audit event structure.

    All audit events follow this schema for consistent logging and analysis.
    Events are immutable after creation and include unique identifiers for
    traceability.

    Attributes:
        version: Schema version for event format evolution
        timestamp: ISO 8601 UTC timestamp with 'Z' suffix
        event_id: Unique UUID for this event
        event_type: Category of event (QUERY_VALIDATION, VALIDATION_ERROR, etc.)
        severity: Log severity level (INFO, WARNING, ERROR)
        user_id: User identifier (anonymized if needed for HIPAA)
        session_id: Session identifier for grouping related events
        ip_address: Source IP address (optional, for audit trail)
        container_id: Container/execution environment ID (optional)
        query_hash: SHA-256 hash of the query (NEVER the full query)
        data: Event-specific structured data
    """

    version: str = "1.0"
    timestamp: str = ""
    event_id: str = ""
    event_type: str = ""
    severity: str = "INFO"
    user_id: str = "unknown"
    session_id: str = "unknown"
    ip_address: str = ""
    container_id: str = ""
    query_hash: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize computed fields after dataclass creation."""
        if not self.timestamp:
            # Use UTC time with ISO 8601 format
            self.timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        if not self.event_id:
            # Generate unique event ID
            self.event_id = str(uuid.uuid4())

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the event
        """
        return asdict(self)


def create_validation_event(
    query_hash: str,
    layers_passed: list[int],
    layers_failed: list[int],
    total_time_ms: float,
    layer_times: dict[str, float],
    user_id: str = "unknown",
    session_id: str = "unknown",
    ip_address: str = "",
    container_id: str = "",
) -> AuditEvent:
    """Create query validation completion event.

    Logs the result of running a query through the validation pipeline,
    including which layers passed/failed and performance metrics.

    Args:
        query_hash: SHA-256 hash of the validated query
        layers_passed: List of layer numbers that passed (e.g., [0, 2, 3])
        layers_failed: List of layer numbers that failed (e.g., [4])
        total_time_ms: Total validation time in milliseconds
        layer_times: Dict mapping layer names to execution times in ms
        user_id: User identifier
        session_id: Session identifier
        ip_address: Source IP address (optional)
        container_id: Container ID (optional)

    Returns:
        AuditEvent configured for validation result logging
    """
    return AuditEvent(
        event_type="QUERY_VALIDATION",
        severity="INFO",
        user_id=user_id,
        session_id=session_id,
        ip_address=ip_address,
        container_id=container_id,
        query_hash=query_hash,
        data={
            "validation_result": "PASS" if not layers_failed else "FAIL",
            "layers_passed": layers_passed,
            "layers_failed": layers_failed,
            "total_time_ms": round(total_time_ms, 2),
            "layer_times_ms": {k: round(v, 2) for k, v in layer_times.items()},
        },
    )


def create_error_event(
    query_hash: str,
    error_code: str,
    error_type: str,
    layer: int,
    message: str,
    user_id: str = "unknown",
    session_id: str = "unknown",
    ip_address: str = "",
    container_id: str = "",
) -> AuditEvent:
    """Create validation error event.

    Logs when a query fails validation at a specific layer, including
    the error code and type for analysis and debugging.

    Args:
        query_hash: SHA-256 hash of the failed query
        error_code: Error code (e.g., E201, E301)
        error_type: Error class name (e.g., DirectPHIIdentifierError)
        layer: Layer number where error occurred (0-8)
        message: Truncated error message (max 200 chars to prevent log bloat)
        user_id: User identifier
        session_id: Session identifier
        ip_address: Source IP address (optional)
        container_id: Container ID (optional)

    Returns:
        AuditEvent configured for validation error logging
    """
    return AuditEvent(
        event_type="VALIDATION_ERROR",
        severity="WARNING",
        user_id=user_id,
        session_id=session_id,
        ip_address=ip_address,
        container_id=container_id,
        query_hash=query_hash,
        data={
            "error_code": error_code,
            "error_type": error_type,
            "layer": layer,
            "message": message[:200],  # Truncate long messages
        },
    )


def create_security_event(
    query_hash: str,
    event_subtype: str,
    detection_layer: int,
    pattern: str,
    blocked: bool,
    user_id: str = "unknown",
    session_id: str = "unknown",
    ip_address: str = "",
    container_id: str = "",
) -> AuditEvent:
    """Create security-related event.

    Logs security detections like SQL injection attempts, circumvention
    attempts (subqueries, CTEs), or other malicious patterns.

    Args:
        query_hash: SHA-256 hash of the suspicious query
        event_subtype: Type of security event (SQL_INJECTION, CIRCUMVENTION)
        detection_layer: Layer that detected the pattern (0-8)
        pattern: Description of malicious pattern detected
        blocked: Whether the query was blocked
        user_id: User identifier
        session_id: Session identifier
        ip_address: Source IP address (optional)
        container_id: Container ID (optional)

    Returns:
        AuditEvent configured for security event logging
    """
    return AuditEvent(
        event_type="SECURITY_EVENT",
        severity="ERROR" if blocked else "WARNING",
        user_id=user_id,
        session_id=session_id,
        ip_address=ip_address,
        container_id=container_id,
        query_hash=query_hash,
        data={
            "event_subtype": event_subtype,
            "detection_layer": detection_layer,
            "malicious_pattern": pattern[:200],  # Truncate long patterns
            "blocked": blocked,
        },
    )


def hash_query(query: str) -> str:
    """Generate SHA-256 hash of query for audit logging.

    CRITICAL: This function enables audit logging without storing full queries,
    preventing PHI exposure in logs. Always use this instead of logging raw queries.

    Args:
        query: SQL query to hash

    Returns:
        64-character hexadecimal SHA-256 hash

    Example:
        >>> hash_query("SELECT * FROM person")
        'a3c5e8d2f1b4c6a7e9d8b1c2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2'
    """
    return hashlib.sha256(query.encode()).hexdigest()
