"""HIPAA-compliant audit logger with tamper-evident signing.

This module implements a production-ready audit logger that meets HIPAA
requirements for audit controls (45 CFR § 164.312(b)) and retention
(45 CFR § 164.530(j)).

Features:
- JSONL format (one event per line for efficient parsing)
- HMAC-SHA256 signing for tamper detection
- Time-based log rotation (daily by default)
- 6-year retention (2190 daily backups)
- Singleton pattern for consistent logging across application

Security:
- Logs are signed with HMAC-SHA256 to detect modifications
- Signing key should be stored in environment variable
- Logs are append-only (handled by filesystem permissions)
- Never logs full queries (only SHA-256 hashes)
"""

import hashlib
import hmac
import json
import logging
import os
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Optional

from src.audit.events import AuditEvent


class JSONLFormatter(logging.Formatter):
    """Format log records as JSONL with optional HMAC signing.

    Each log record is formatted as a single line of JSON. If a signing key
    is provided, an HMAC-SHA256 signature is added to each record for
    tamper detection.

    Attributes:
        signing_key: Optional HMAC signing key (bytes)
    """

    def __init__(self, signing_key: bytes | None = None):
        """Initialize formatter.

        Args:
            signing_key: Optional HMAC signing key (minimum 32 bytes recommended)
        """
        super().__init__()
        self.signing_key = signing_key

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON line.

        Args:
            record: Log record to format

        Returns:
            JSON string representing the log record
        """
        # Get event from record
        if hasattr(record, "event"):
            event_dict = record.event.to_dict()
        else:
            # Fallback for non-event logs (shouldn't happen in normal use)
            event_dict = {
                "timestamp": self.formatTime(record),
                "level": record.levelname,
                "message": record.getMessage(),
            }

        # Add signature if key provided
        if self.signing_key:
            event_dict = self._sign_event(event_dict)

        return json.dumps(event_dict)

    def _sign_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Add HMAC-SHA256 signature to event.

        The signature is computed over the canonical JSON representation
        (sorted keys) of the event to ensure consistent signing.

        Args:
            event: Event dictionary to sign

        Returns:
            Event dictionary with 'signature' field added
        """
        # Ensure signing key is not None (should be checked by caller)
        if self.signing_key is None:
            msg = "Signing key must not be None"
            raise ValueError(msg)

        # Create canonical JSON representation (sorted keys for consistency)
        event_json = json.dumps(event, sort_keys=True)

        # Generate HMAC-SHA256 signature
        signature = hmac.new(self.signing_key, event_json.encode(), hashlib.sha256).hexdigest()

        # Add signature to event
        event["signature"] = signature
        return event


class AuditLogger:
    """HIPAA-compliant audit logger with rotation and signing.

    This is a singleton logger that provides tamper-evident audit logging
    in JSONL format with automatic rotation and configurable retention.

    The logger is thread-safe and can be safely accessed from multiple
    parts of the application.

    Example:
        >>> from src.audit.logger import audit_logger
        >>> from src.audit.events import AuditEvent
        >>>
        >>> event = AuditEvent(
        ...     event_type="QUERY_VALIDATION",
        ...     query_hash="abc123...",
        ...     data={"result": "PASS"}
        ... )
        >>> audit_logger.log_event(event)
    """

    _instance: Optional["AuditLogger"] = None
    _initialized: bool = False

    def __new__(cls, *args: Any, **kwargs: Any) -> "AuditLogger":
        """Ensure singleton pattern.

        Returns:
            The single AuditLogger instance
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(
        self,
        log_dir: str = "/var/log/hipaa_validator",
        signing_key: bytes | None = None,
        rotation: str = "midnight",
        backup_count: int = 2190,  # 6 years of daily logs
    ):
        """Initialize audit logger.

        Only initializes once (singleton pattern). Subsequent calls with
        different parameters will be ignored.

        Args:
            log_dir: Directory for audit logs
            signing_key: Optional HMAC signing key (fetched from env if None)
            rotation: Rotation schedule ('midnight', 'H' for hourly, etc.)
            backup_count: Number of backup files to keep (2190 = 6 years daily)
        """
        # Skip initialization if already done
        if self._initialized:
            return

        # Create log directory
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Get signing key from environment if not provided
        if signing_key is None:
            key_str = os.environ.get("AUDIT_SIGNING_KEY", "")
            signing_key = key_str.encode() if key_str else None

        # Create logger
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False  # Don't propagate to root logger

        # Remove existing handlers (in case of re-initialization)
        self.logger.handlers.clear()

        # Create rotating file handler
        log_file = self.log_dir / "audit.jsonl"
        handler = TimedRotatingFileHandler(
            filename=str(log_file),
            when=rotation,
            interval=1,
            backupCount=backup_count,
            encoding="utf-8",
        )

        # Set formatter with signing
        formatter = JSONLFormatter(signing_key=signing_key)
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)
        self._initialized = True

    def log_event(self, event: AuditEvent) -> None:
        """Log audit event.

        Args:
            event: AuditEvent to log
        """
        # Create log record with event attached
        record = self.logger.makeRecord(
            name=self.logger.name,
            level=logging.INFO,
            fn="",
            lno=0,
            msg="",
            args=(),
            exc_info=None,
        )
        record.event = event

        self.logger.handle(record)

        # Flush handlers to ensure immediate write (important for audit logs)
        for handler in self.logger.handlers:
            handler.flush()

    def log_validation(self, event: AuditEvent) -> None:
        """Log validation event.

        Convenience method for logging validation events.

        Args:
            event: Validation event to log
        """
        self.log_event(event)

    def log_error(self, event: AuditEvent) -> None:
        """Log error event.

        Convenience method for logging error events.

        Args:
            event: Error event to log
        """
        self.log_event(event)

    def log_security(self, event: AuditEvent) -> None:
        """Log security event.

        Convenience method for logging security events.

        Args:
            event: Security event to log
        """
        self.log_event(event)

    @classmethod
    def _reset_instance(cls) -> None:
        """Reset singleton instance (for testing only).

        WARNING: This method should only be used in tests to reset the
        singleton state between test cases. Never use in production code.
        """
        if cls._instance is not None:
            # Clean up existing handlers
            if hasattr(cls._instance, "logger"):
                for handler in cls._instance.logger.handlers:
                    handler.close()
                cls._instance.logger.handlers.clear()
        cls._instance = None


# Global singleton instance
# Import this in other modules: from src.audit.logger import audit_logger
audit_logger = AuditLogger()


def log_event(event: AuditEvent) -> None:
    """Convenience function to log event using global singleton.

    Args:
        event: AuditEvent to log

    Example:
        >>> from src.audit.logger import log_event
        >>> from src.audit.events import AuditEvent
        >>>
        >>> event = AuditEvent(event_type="TEST")
        >>> log_event(event)
    """
    audit_logger.log_event(event)
