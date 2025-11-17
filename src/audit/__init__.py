"""HIPAA-compliant audit logging.

This module provides tamper-evident audit logging in JSONL format with
6-year retention for HIPAA compliance (45 CFR § 164.312(b) and 164.530(j)).

Key features:
- JSONL event format
- HMAC-SHA256 log signing
- Query hashing (NEVER logs full queries to prevent PHI exposure)
- Time-based log rotation with 6-year retention
- Comprehensive event tracking

Modules:
- events: Audit event definitions and creation functions
- logger: HIPAA-compliant JSONL logger with signing and rotation
"""

from src.audit.events import (
    AuditEvent,
    create_error_event,
    create_security_event,
    create_validation_event,
    hash_query,
)
from src.audit.logger import AuditLogger, audit_logger, log_event

__all__ = [
    "AuditEvent",
    "create_validation_event",
    "create_error_event",
    "create_security_event",
    "hash_query",
    "AuditLogger",
    "audit_logger",
    "log_event",
]
