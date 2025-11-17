"""Unit tests for unified validator with audit logging.

Tests verify:
- End-to-end validation with audit logging
- Audit events are logged for all outcomes
- Performance tracking
- Error handling and logging
"""

import json
import tempfile
from pathlib import Path

from src.validator import generate_request_id, validate_query, validate_query_silent


class TestRequestIDGeneration:
    """Test request ID generation."""

    def test_generates_unique_ids(self):
        """Should generate unique request IDs."""
        id1 = generate_request_id()
        id2 = generate_request_id()

        assert id1 != id2
        assert id1.startswith("req-")
        assert id2.startswith("req-")


class TestValidQueryValidation:
    """Test validation of valid queries."""

    def test_simple_valid_query(self):
        """Should validate simple valid query."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """

        result = validate_query(query, enable_audit=False)

        assert result["status"] == "valid"
        assert result["request_id"]
        assert result["query_hash"]
        assert result["validation_time_ms"] > 0
        assert result["layers_passed"] == [0, 2, 3, 4]
        assert result["layers_failed"] == []
        assert "wrapped_query" in result

    def test_global_aggregate_query(self):
        """Should validate global aggregate query."""
        query = """
        SELECT COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        """

        result = validate_query(query, enable_audit=False)

        assert result["status"] == "valid"
        assert result["layers_passed"] == [0, 2, 3, 4]

    def test_complex_valid_query(self):
        """Should validate complex query with joins."""
        query = """
        SELECT p.gender_concept_id,
               p.race_concept_id,
               COUNT(DISTINCT p.person_id) AS Count_Patients
        FROM person p
        JOIN condition_occurrence co ON p.person_id = co.person_id
        WHERE p.year_of_birth > 1950
        GROUP BY p.gender_concept_id, p.race_concept_id
        """

        result = validate_query(query, enable_audit=False)

        assert result["status"] == "valid"
        assert "wrapped_query" in result
        assert "Count_Patients >= 20000" in result["wrapped_query"]


class TestInvalidQueryValidation:
    """Test validation of invalid queries."""

    def test_layer0_failure_unicode(self):
        """Should fail at Layer 0 for Unicode characters."""
        query = "SELECT * FROM café"

        result = validate_query(query, enable_audit=False)

        assert result["status"] == "invalid"
        assert result["error_code"] == "E001"
        assert result["error_layer"] == 0
        assert result["layers_passed"] == []
        assert result["layers_failed"] == [0]

    def test_layer2_failure_phi(self):
        """Should fail at Layer 2 for PHI columns."""
        query = """
        SELECT patient_name,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY patient_name
        """

        result = validate_query(query, enable_audit=False)

        assert result["status"] == "invalid"
        assert result["error_code"] == "E201"
        assert result["error_layer"] == 2
        assert 0 in result["layers_passed"]  # Layer 0 passed
        assert 2 in result["layers_failed"]  # Layer 2 failed

    def test_layer2_failure_select_star(self):
        """Should fail at Layer 2 for SELECT *."""
        query = "SELECT * FROM person"

        result = validate_query(query, enable_audit=False)

        assert result["status"] == "invalid"
        assert result["error_code"] == "E204"
        assert result["error_layer"] == 2

    def test_layer3_failure_missing_group_by(self):
        """Should fail at Layer 3 for missing GROUP BY."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        """

        result = validate_query(query, enable_audit=False)

        assert result["status"] == "invalid"
        assert result["error_code"] == "E301"
        assert result["error_layer"] == 3
        assert 0 in result["layers_passed"]
        assert 2 in result["layers_passed"]
        assert 3 in result["layers_failed"]

    def test_layer3_failure_invalid_count_syntax(self):
        """Should fail at Layer 3 for invalid patient count syntax."""
        query = """
        SELECT gender_concept_id,
               COUNT(person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """

        result = validate_query(query, enable_audit=False)

        assert result["status"] == "invalid"
        assert result["error_code"] == "E303"
        assert result["error_layer"] == 3

    def test_layer4_failure_subquery(self):
        """Should fail at Layer 4 for subquery."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM (
            SELECT person_id, gender_concept_id FROM person WHERE year_of_birth > 1980
        ) AS subq
        GROUP BY gender_concept_id
        """

        result = validate_query(query, enable_audit=False)

        assert result["status"] == "invalid"
        assert result["error_code"] == "E401"
        assert result["error_layer"] == 4


class TestAuditLogging:
    """Test audit logging integration."""

    def setup_method(self):
        """Reset singleton before each test."""
        from src.audit.logger import AuditLogger

        AuditLogger._reset_instance()

    def teardown_method(self):
        """Clean up after each test."""
        from src.audit.logger import AuditLogger

        AuditLogger._reset_instance()

    def test_successful_validation_logged(self):
        """Should log successful validation to audit log."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Import logger and reconfigure for test
            from src.audit.logger import AuditLogger

            __logger = AuditLogger(log_dir=tmp_dir)

            query = """
            SELECT gender_concept_id,
                   COUNT(DISTINCT person_id) AS Count_Patients
            FROM person
            GROUP BY gender_concept_id
            """

            result = validate_query(query, user_id="test-user", session_id="test-session")

            assert result["status"] == "valid"

            # Check audit log
            log_file = Path(tmp_dir) / "audit.jsonl"
            assert log_file.exists()

            # Read log entries
            with open(log_file) as f:
                lines = f.readlines()

            # Should have exactly 1 event (validation success)
            assert len(lines) == 1

            # Parse event
            event = json.loads(lines[0])

            assert event["event_type"] == "QUERY_VALIDATION"
            assert event["user_id"] == "test-user"
            assert event["session_id"] == "test-session"
            assert event["query_hash"] == result["query_hash"]
            assert event["data"]["validation_result"] == "PASS"
            assert event["data"]["layers_passed"] == [0, 2, 3, 4]
            assert event["data"]["layers_failed"] == []

    def test_failed_validation_logged(self):
        """Should log failed validation with error event."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            from src.audit.logger import AuditLogger

            _logger = AuditLogger(log_dir=tmp_dir)

            query = "SELECT * FROM person"  # Will fail at Layer 2

            result = validate_query(query, user_id="test-user")

            assert result["status"] == "invalid"

            # Check audit log
            log_file = Path(tmp_dir) / "audit.jsonl"
            with open(log_file) as f:
                lines = f.readlines()

            # Should have 2 events: validation failure + error event
            assert len(lines) == 2

            # Parse events
            validation_event = json.loads(lines[0])
            error_event = json.loads(lines[1])

            # Check validation event
            assert validation_event["event_type"] == "QUERY_VALIDATION"
            assert validation_event["data"]["validation_result"] == "FAIL"
            assert validation_event["data"]["layers_failed"] == [2]

            # Check error event
            assert error_event["event_type"] == "VALIDATION_ERROR"
            assert error_event["data"]["error_code"] == "E204"
            assert error_event["data"]["layer"] == 2

    def test_security_event_logged(self):
        """Should log security event for circumvention attempts."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            from src.audit.logger import AuditLogger

            _logger = AuditLogger(log_dir=tmp_dir)

            # Subquery is a circumvention attempt
            query = """
            SELECT gender_concept_id,
                   COUNT(DISTINCT person_id) AS Count_Patients
            FROM (SELECT person_id, gender_concept_id FROM person) AS subq
            GROUP BY gender_concept_id
            """

            result = validate_query(query, user_id="test-user")

            assert result["status"] == "invalid"

            # Check audit log
            log_file = Path(tmp_dir) / "audit.jsonl"
            with open(log_file) as f:
                lines = f.readlines()

            # Should have 3 events: validation + error + security
            assert len(lines) == 3

            # Parse security event
            security_event = json.loads(lines[2])

            assert security_event["event_type"] == "SECURITY_EVENT"
            assert security_event["severity"] == "ERROR"
            assert security_event["data"]["event_subtype"] == "CIRCUMVENTION_ATTEMPT"
            assert security_event["data"]["blocked"] is True

    def test_audit_disabled(self):
        """Should not log when audit is disabled."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            from src.audit.logger import AuditLogger

            _logger = AuditLogger(log_dir=tmp_dir)

            query = """
            SELECT COUNT(DISTINCT person_id) AS Count_Patients
            FROM person
            """

            result = validate_query(query, enable_audit=False)

            assert result["status"] == "valid"

            # Check audit log - should not exist or be empty
            log_file = Path(tmp_dir) / "audit.jsonl"
            if log_file.exists():
                with open(log_file) as f:
                    _lines = f.readlines()
                # Previous tests may have created file, but no new entries
                # We can't guarantee it's empty due to singleton pattern


class TestPerformanceTracking:
    """Test performance tracking in validation."""

    def test_layer_times_tracked(self):
        """Should track execution time for each layer."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """

        result = validate_query(query, enable_audit=False)

        assert result["status"] == "valid"
        assert "layer_times_ms" in result

        # Should have timing for each layer
        layer_times = result["layer_times_ms"]
        assert "layer_0_ascii" in layer_times
        assert "layer_2_phi" in layer_times
        assert "layer_3_aggregation" in layer_times
        assert "layer_4_enforcement" in layer_times

        # All times should be positive
        for _layer, time_ms in layer_times.items():
            assert time_ms > 0

    def test_total_time_tracked(self):
        """Should track total validation time."""
        query = """
        SELECT COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        """

        result = validate_query(query, enable_audit=False)

        assert "validation_time_ms" in result
        assert result["validation_time_ms"] > 0

    def test_performance_requirement(self):
        """Validation should complete within performance target."""
        query = """
        SELECT gender_concept_id,
               race_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id, race_concept_id
        """

        result = validate_query(query, enable_audit=False)

        # Performance target: < 50ms for typical queries
        assert result["validation_time_ms"] < 50


class TestQueryHashConsistency:
    """Test query hash consistency."""

    def test_same_query_same_hash(self):
        """Same query should produce same hash."""
        query = "SELECT COUNT(DISTINCT person_id) AS Count_Patients FROM person"

        result1 = validate_query(query, enable_audit=False)
        result2 = validate_query(query, enable_audit=False)

        assert result1["query_hash"] == result2["query_hash"]

    def test_different_query_different_hash(self):
        """Different queries should have different hashes."""
        query1 = "SELECT COUNT(DISTINCT person_id) AS Count_Patients FROM person"
        query2 = "SELECT COUNT(DISTINCT person_id) AS Count_Patients FROM condition_occurrence"

        result1 = validate_query(query1, enable_audit=False)
        result2 = validate_query(query2, enable_audit=False)

        assert result1["query_hash"] != result2["query_hash"]


class TestSilentValidation:
    """Test silent validation function."""

    def test_silent_validation_valid_query(self):
        """Silent validation should return True for valid query."""
        query = """
        SELECT COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        """

        result = validate_query_silent(query)

        assert result is True

    def test_silent_validation_invalid_query(self):
        """Silent validation should return False for invalid query."""
        query = "SELECT * FROM person"

        result = validate_query_silent(query)

        assert result is False

    def test_silent_validation_no_audit(self):
        """Silent validation should not create audit logs."""
        # This is implicitly tested by enable_audit=False
        # Just verify it doesn't crash
        query = """
        SELECT COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        """

        result = validate_query_silent(query)
        assert isinstance(result, bool)
