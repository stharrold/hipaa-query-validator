"""Data models for HIPAA Query Validator.

This module defines the core data structures used throughout the validation
system, including validation results, query metadata, and audit information.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ValidationResult:
    """Result of a query validation operation.

    Attributes:
        success: Whether the validation passed
        request_id: Unique identifier for this validation request
        layer: Name of the validation layer (e.g., 'ascii_input', 'phi', 'aggregation')
        code: Error code (e.g., 'E001', 'E201') or None if successful
        message: Human-readable error or success message
        educational_guidance: Educational guidance for fixing the issue
        correct_pattern: Example of correct pattern/syntax
        timestamp: ISO 8601 timestamp of validation
        details: Additional context-specific details
    """

    success: bool
    request_id: str
    layer: str | None = None
    code: str | None = None
    message: str | None = None
    educational_guidance: str | None = None
    correct_pattern: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert validation result to dictionary for serialization."""
        return {
            "success": self.success,
            "request_id": self.request_id,
            "layer": self.layer,
            "code": self.code,
            "message": self.message,
            "educational_guidance": self.educational_guidance,
            "correct_pattern": self.correct_pattern,
            "timestamp": self.timestamp,
            "details": self.details,
        }


@dataclass
class QueryMetadata:
    """Metadata about a validated query.

    Attributes:
        query_hash: SHA-256 hash of the normalized query
        validation_time_ms: Total validation time in milliseconds
        layer_times: Validation time per layer in milliseconds
        layers_passed: List of validation layers that passed
        total_layers: Total number of validation layers executed
    """

    query_hash: str
    validation_time_ms: float
    layer_times: dict[str, float] = field(default_factory=dict)
    layers_passed: list[str] = field(default_factory=list)
    total_layers: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert query metadata to dictionary for serialization."""
        return {
            "query_hash": self.query_hash,
            "validation_time_ms": self.validation_time_ms,
            "layer_times": self.layer_times,
            "layers_passed": self.layers_passed,
            "total_layers": self.total_layers,
        }


@dataclass
class AuditLogEntry:
    """Audit log entry for compliance tracking.

    Per HIPAA requirements, audit logs must be retained for 6 years and
    include sufficient detail for incident investigation.

    Attributes:
        request_id: Unique identifier linking to validation result
        timestamp: ISO 8601 timestamp
        user_id: Identifier of user who submitted the query (if available)
        query_hash: SHA-256 hash of the query
        validation_result: Outcome (PASS, FAIL, ERROR)
        layer_failed: Validation layer that failed (if any)
        error_code: Error code (if failed)
        ip_address: Source IP address (if available)
        session_id: Session identifier (if available)
    """

    request_id: str
    timestamp: str
    query_hash: str
    validation_result: str  # PASS, FAIL, or ERROR
    layer_failed: str | None = None
    error_code: str | None = None
    user_id: str | None = None
    ip_address: str | None = None
    session_id: str | None = None

    def to_jsonl(self) -> str:
        """Convert audit log entry to JSONL format for append-only logging."""
        import json

        return json.dumps(
            {
                "request_id": self.request_id,
                "timestamp": self.timestamp,
                "user_id": self.user_id,
                "query_hash": self.query_hash,
                "validation_result": self.validation_result,
                "layer_failed": self.layer_failed,
                "error_code": self.error_code,
                "ip_address": self.ip_address,
                "session_id": self.session_id,
            }
        )


@dataclass
class PHIIdentifier:
    """Definition of a PHI identifier per 45 CFR § 164.514(b)(2).

    Attributes:
        name: Name of the identifier (e.g., 'patient_name', 'ssn')
        category: Category (direct_identifier, geographic, date, etc.)
        column_patterns: List of regex patterns to match column names
        description: Human-readable description
        cfr_reference: Reference to specific CFR section
    """

    name: str
    category: str
    column_patterns: list[str]
    description: str
    cfr_reference: str = "45 CFR § 164.514(b)(2)"

    def to_dict(self) -> dict[str, Any]:
        """Convert PHI identifier to dictionary."""
        return {
            "name": self.name,
            "category": self.category,
            "column_patterns": self.column_patterns,
            "description": self.description,
            "cfr_reference": self.cfr_reference,
        }
