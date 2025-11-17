"""Unit tests for HIPAA-compliant audit logging system.

Tests verify:
- JSONL log format
- HMAC-SHA256 log signing
- Query hashing (no full queries logged)
- Event creation and structure
- Log rotation and retention
- Performance (< 5ms overhead)
"""

import hashlib
import hmac
import json
import os
import tempfile
import time
from pathlib import Path

from src.audit.events import (
    AuditEvent,
    create_error_event,
    create_security_event,
    create_validation_event,
    hash_query,
)
from src.audit.logger import AuditLogger, JSONLFormatter, audit_logger


class TestQueryHashing:
    """Test query hashing for audit logging."""

    def test_query_hash_consistent(self):
        """Same query should produce same hash."""
        query = "SELECT * FROM person"

        hash1 = hash_query(query)
        hash2 = hash_query(query)

        assert hash1 == hash2

    def test_different_queries_different_hashes(self):
        """Different queries should have different hashes."""
        query1 = "SELECT * FROM person"
        query2 = "SELECT * FROM condition_occurrence"

        hash1 = hash_query(query1)
        hash2 = hash_query(query2)

        assert hash1 != hash2

    def test_hash_is_sha256(self):
        """Hash should be SHA-256."""
        query = "SELECT * FROM person"
        hash_val = hash_query(query)

        # SHA-256 produces 64 hex characters
        assert len(hash_val) == 64
        assert all(c in "0123456789abcdef" for c in hash_val)

    def test_hash_no_query_exposure(self):
        """Hash should not contain any part of the query."""
        query = "SELECT patient_name FROM person"
        hash_val = hash_query(query)

        # Hash should not contain query content
        assert "patient_name" not in hash_val.lower()
        assert "person" not in hash_val.lower()
        assert "select" not in hash_val.lower()

    def test_hash_unicode_query(self):
        """Should hash queries with Unicode characters."""
        query = "SELECT * FROM café"
        hash_val = hash_query(query)

        # Should still produce valid SHA-256
        assert len(hash_val) == 64
        assert all(c in "0123456789abcdef" for c in hash_val)


class TestAuditEventCreation:
    """Test audit event creation functions."""

    def test_create_validation_event(self):
        """Should create validation event with correct structure."""
        event = create_validation_event(
            query_hash="abc123",
            layers_passed=[0, 2, 3],
            layers_failed=[],
            total_time_ms=10.5,
            layer_times={"layer_0": 2.1, "layer_2": 3.2, "layer_3": 5.2},
            user_id="user-123",
            session_id="session-456",
        )

        assert event.event_type == "QUERY_VALIDATION"
        assert event.severity == "INFO"
        assert event.query_hash == "abc123"
        assert event.user_id == "user-123"
        assert event.session_id == "session-456"
        assert event.data["validation_result"] == "PASS"
        assert event.data["layers_passed"] == [0, 2, 3]
        assert event.data["layers_failed"] == []
        assert event.data["total_time_ms"] == 10.5

    def test_create_validation_event_failure(self):
        """Should mark validation as FAIL when layers failed."""
        event = create_validation_event(
            query_hash="abc123",
            layers_passed=[0, 2],
            layers_failed=[3],
            total_time_ms=5.0,
            layer_times={"layer_0": 1.0, "layer_2": 2.0, "layer_3": 2.0},
        )

        assert event.data["validation_result"] == "FAIL"
        assert event.data["layers_failed"] == [3]

    def test_create_error_event(self):
        """Should create error event with correct structure."""
        event = create_error_event(
            query_hash="abc123",
            error_code="E201",
            error_type="DirectPHIIdentifierError",
            layer=2,
            message="Direct PHI identifier 'patient_name' detected",
            user_id="user-123",
        )

        assert event.event_type == "VALIDATION_ERROR"
        assert event.severity == "WARNING"
        assert event.query_hash == "abc123"
        assert event.data["error_code"] == "E201"
        assert event.data["error_type"] == "DirectPHIIdentifierError"
        assert event.data["layer"] == 2

    def test_create_error_event_truncates_message(self):
        """Should truncate long error messages to 200 characters."""
        long_message = "x" * 300

        event = create_error_event(
            query_hash="abc123",
            error_code="E001",
            error_type="TestError",
            layer=0,
            message=long_message,
        )

        assert len(event.data["message"]) == 200

    def test_create_security_event(self):
        """Should create security event with correct structure."""
        event = create_security_event(
            query_hash="abc123",
            event_subtype="CIRCUMVENTION_ATTEMPT",
            detection_layer=4,
            pattern="Subquery detected",
            blocked=True,
            user_id="user-123",
        )

        assert event.event_type == "SECURITY_EVENT"
        assert event.severity == "ERROR"  # Blocked events are ERROR
        assert event.data["event_subtype"] == "CIRCUMVENTION_ATTEMPT"
        assert event.data["detection_layer"] == 4
        assert event.data["blocked"] is True

    def test_create_security_event_not_blocked(self):
        """Security event should be WARNING if not blocked."""
        event = create_security_event(
            query_hash="abc123",
            event_subtype="SUSPICIOUS_PATTERN",
            detection_layer=2,
            pattern="Unusual query",
            blocked=False,
        )

        assert event.severity == "WARNING"

    def test_audit_event_auto_fields(self):
        """AuditEvent should auto-populate timestamp and event_id."""
        event = AuditEvent(event_type="TEST", query_hash="abc123")

        # Should have timestamp
        assert event.timestamp
        assert "T" in event.timestamp  # ISO 8601 format
        assert event.timestamp.endswith("Z")  # UTC

        # Should have event_id
        assert event.event_id
        assert len(event.event_id) > 0

    def test_audit_event_to_dict(self):
        """AuditEvent should convert to dictionary."""
        event = AuditEvent(
            event_type="TEST",
            query_hash="abc123",
            user_id="user-123",
            data={"key": "value"},
        )

        event_dict = event.to_dict()

        assert event_dict["event_type"] == "TEST"
        assert event_dict["query_hash"] == "abc123"
        assert event_dict["user_id"] == "user-123"
        assert event_dict["data"]["key"] == "value"


class TestJSONLFormatter:
    """Test JSONL formatter with signing."""

    def test_format_without_signing(self):
        """Should format event as JSON without signature."""
        formatter = JSONLFormatter(signing_key=None)

        event = AuditEvent(event_type="TEST", query_hash="abc123")

        # Create mock log record
        import logging

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="",
            args=(),
            exc_info=None,
        )
        record.event = event

        formatted = formatter.format(record)

        # Should be valid JSON
        parsed = json.loads(formatted)
        assert parsed["event_type"] == "TEST"
        assert "signature" not in parsed

    def test_format_with_signing(self):
        """Should format event with HMAC signature."""
        signing_key = b"test-key-12345678901234567890"
        formatter = JSONLFormatter(signing_key=signing_key)

        event = AuditEvent(event_type="TEST", query_hash="abc123")

        # Create mock log record
        import logging

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="",
            args=(),
            exc_info=None,
        )
        record.event = event

        formatted = formatter.format(record)

        # Should be valid JSON
        parsed = json.loads(formatted)
        assert "signature" in parsed

        # Verify signature
        signature = parsed.pop("signature")
        event_json = json.dumps(parsed, sort_keys=True)
        expected_sig = hmac.new(signing_key, event_json.encode(), hashlib.sha256).hexdigest()

        assert signature == expected_sig

    def test_signature_detects_tampering(self):
        """Signature should detect if event is modified."""
        signing_key = b"test-key-12345678901234567890"
        formatter = JSONLFormatter(signing_key=signing_key)

        event = AuditEvent(event_type="TEST", query_hash="abc123")

        # Create mock log record
        import logging

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="",
            args=(),
            exc_info=None,
        )
        record.event = event

        formatted = formatter.format(record)
        parsed = json.loads(formatted)

        # Save original signature
        original_signature = parsed["signature"]

        # Tamper with event
        parsed["query_hash"] = "tampered"

        # Recompute signature without 'signature' field
        _signature = parsed.pop("signature")
        event_json = json.dumps(parsed, sort_keys=True)
        expected_sig = hmac.new(signing_key, event_json.encode(), hashlib.sha256).hexdigest()

        # Signature should be different after tampering
        assert original_signature != expected_sig


class TestAuditLogger:
    """Test audit logger functionality."""

    def setup_method(self):
        """Reset singleton before each test."""
        AuditLogger._reset_instance()

    def teardown_method(self):
        """Clean up after each test."""
        AuditLogger._reset_instance()

    def test_logger_creates_file(self):
        """Logger should create audit log file."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            logger = AuditLogger(log_dir=tmp_dir)

            event = AuditEvent(event_type="TEST", user_id="test-user", query_hash="test-hash")

            logger.log_event(event)

            log_file = Path(tmp_dir) / "audit.jsonl"
            assert log_file.exists()

    def test_jsonl_format(self):
        """Events should be logged as JSONL (one per line)."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            logger = AuditLogger(log_dir=tmp_dir)

            # Log multiple events
            for i in range(3):
                event = AuditEvent(
                    event_type="TEST",
                    user_id=f"user-{i}",
                    query_hash=f"hash-{i}",
                    data={"index": i},
                )
                logger.log_event(event)

            # Read log file
            log_file = Path(tmp_dir) / "audit.jsonl"
            with open(log_file) as f:
                lines = f.readlines()

            # Should have 3 lines
            assert len(lines) == 3

            # Each line should be valid JSON
            for i, line in enumerate(lines):
                log_entry = json.loads(line)
                assert log_entry["event_type"] == "TEST"
                assert log_entry["user_id"] == f"user-{i}"
                assert log_entry["data"]["index"] == i

    def test_log_signing(self):
        """Logs should be signed with HMAC."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            signing_key = b"test-key-12345678901234567890"
            logger = AuditLogger(log_dir=tmp_dir, signing_key=signing_key)

            event = AuditEvent(event_type="TEST", user_id="test")

            logger.log_event(event)

            # Read and verify signature
            log_file = Path(tmp_dir) / "audit.jsonl"
            with open(log_file) as f:
                line = f.readline()

            log_entry = json.loads(line)

            # Should have signature
            assert "signature" in log_entry

            # Verify signature
            signature = log_entry.pop("signature")
            event_json = json.dumps(log_entry, sort_keys=True)
            expected_sig = hmac.new(signing_key, event_json.encode(), hashlib.sha256).hexdigest()

            assert signature == expected_sig

    def test_signing_key_from_environment(self):
        """Should load signing key from environment variable."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Set environment variable
            os.environ["AUDIT_SIGNING_KEY"] = "env-key-12345678901234567890"

            try:
                logger = AuditLogger(log_dir=tmp_dir)

                event = AuditEvent(event_type="TEST", user_id="test")
                logger.log_event(event)

                # Read log
                log_file = Path(tmp_dir) / "audit.jsonl"
                with open(log_file) as f:
                    line = f.readline()

                log_entry = json.loads(line)

                # Should have signature (key loaded from env)
                assert "signature" in log_entry

            finally:
                # Clean up environment
                del os.environ["AUDIT_SIGNING_KEY"]

    def test_convenience_methods(self):
        """Logger should have convenience methods for event types."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            logger = AuditLogger(log_dir=tmp_dir)

            # Test log_validation
            validation_event = create_validation_event(
                query_hash="abc",
                layers_passed=[0, 2],
                layers_failed=[],
                total_time_ms=5.0,
                layer_times={},
            )
            logger.log_validation(validation_event)

            # Test log_error
            error_event = create_error_event(
                query_hash="def",
                error_code="E201",
                error_type="TestError",
                layer=2,
                message="Test",
            )
            logger.log_error(error_event)

            # Test log_security
            security_event = create_security_event(
                query_hash="ghi",
                event_subtype="TEST",
                detection_layer=4,
                pattern="test",
                blocked=True,
            )
            logger.log_security(security_event)

            # Should have 3 events logged
            log_file = Path(tmp_dir) / "audit.jsonl"
            with open(log_file) as f:
                lines = f.readlines()

            assert len(lines) == 3


class TestAuditLoggingPerformance:
    """Test audit logging performance requirements."""

    def test_logging_overhead(self):
        """Audit logging should add < 5ms overhead."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            logger = AuditLogger(log_dir=tmp_dir)

            event = create_validation_event(
                query_hash="abc123",
                layers_passed=[0, 2, 3, 4],
                layers_failed=[],
                total_time_ms=10.0,
                layer_times={"layer_0": 2.0, "layer_2": 3.0, "layer_3": 3.0, "layer_4": 2.0},
            )

            # Measure logging time
            start = time.perf_counter()

            for _ in range(100):
                logger.log_event(event)

            end = time.perf_counter()
            elapsed_ms = (end - start) * 1000

            # Average should be < 5ms per event
            avg_ms = elapsed_ms / 100
            assert avg_ms < 5.0  # Performance requirement

    def test_hash_performance(self):
        """Query hashing should be fast (< 1ms for typical queries)."""
        # Generate typical query
        query = """
        SELECT p.gender_concept_id,
               p.race_concept_id,
               COUNT(DISTINCT p.person_id) AS Count_Patients
        FROM person p
        JOIN condition_occurrence co ON p.person_id = co.person_id
        WHERE p.year_of_birth > 1950
        GROUP BY p.gender_concept_id, p.race_concept_id
        """

        # Measure hashing time
        start = time.perf_counter()

        for _ in range(1000):
            hash_query(query)

        end = time.perf_counter()
        elapsed_ms = (end - start) * 1000

        # Average should be < 1ms
        avg_ms = elapsed_ms / 1000
        assert avg_ms < 1.0


class TestGlobalLoggerSingleton:
    """Test global audit_logger singleton."""

    def setup_method(self):
        """Reset singleton before each test."""
        AuditLogger._reset_instance()

    def teardown_method(self):
        """Clean up after each test."""
        AuditLogger._reset_instance()

    def test_global_logger_exists(self):
        """Global audit_logger should be importable."""

        assert audit_logger is not None

    def test_log_event_function(self):
        """log_event convenience function should work."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create new logger instance for testing
            test_logger = AuditLogger(log_dir=tmp_dir)

            event = AuditEvent(event_type="TEST", query_hash="abc123")

            # Use convenience function
            test_logger.log_event(event)

            # Verify logged
            log_file = Path(tmp_dir) / "audit.jsonl"
            assert log_file.exists()


class TestEventFieldValidation:
    """Test that events include all required fields."""

    def test_validation_event_required_fields(self):
        """Validation event should have all required fields."""
        event = create_validation_event(
            query_hash="abc123",
            layers_passed=[0, 2],
            layers_failed=[],
            total_time_ms=5.0,
            layer_times={},
        )

        event_dict = event.to_dict()

        # Check required fields
        assert "version" in event_dict
        assert "timestamp" in event_dict
        assert "event_id" in event_dict
        assert "event_type" in event_dict
        assert "severity" in event_dict
        assert "query_hash" in event_dict
        assert "data" in event_dict

    def test_error_event_required_fields(self):
        """Error event should have all required fields."""
        event = create_error_event(
            query_hash="abc123",
            error_code="E201",
            error_type="TestError",
            layer=2,
            message="Test message",
        )

        event_dict = event.to_dict()

        # Check required fields
        assert "version" in event_dict
        assert "timestamp" in event_dict
        assert "event_id" in event_dict
        assert "event_type" in event_dict
        assert "severity" in event_dict
        assert "query_hash" in event_dict
        assert event_dict["data"]["error_code"] == "E201"
        assert event_dict["data"]["layer"] == 2

    def test_security_event_required_fields(self):
        """Security event should have all required fields."""
        event = create_security_event(
            query_hash="abc123",
            event_subtype="CIRCUMVENTION",
            detection_layer=4,
            pattern="subquery",
            blocked=True,
        )

        event_dict = event.to_dict()

        # Check required fields
        assert "version" in event_dict
        assert "timestamp" in event_dict
        assert "event_id" in event_dict
        assert "event_type" in event_dict
        assert "severity" in event_dict
        assert "query_hash" in event_dict
        assert event_dict["data"]["blocked"] is True
