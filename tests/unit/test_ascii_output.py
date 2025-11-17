"""Tests for Layer 8: ASCII output validation.

This module tests the final validation layer that checks query results
to ensure ASCII-only output and HIPAA compliance.
"""

import pytest

from src.errors import (
    NonASCIIOutputError,
    PatientCountBelowThresholdError,
    TooManyRowsError,
)
from src.validators.ascii_output import (
    _check_phi_patterns,
    get_safe_preview,
    validate_ascii_output,
)


class TestValidOutput:
    """Test valid output passes validation."""

    def test_valid_ascii_output(self):
        """Valid ASCII output should pass."""
        result_set = [
            {"Count_Patients": 25000, "gender_concept_id": 8507, "patient_count": 15000},
            {"Count_Patients": 22000, "gender_concept_id": 8532, "patient_count": 10000},
        ]

        result = validate_ascii_output(result_set, "test-001")
        assert result.success is True
        assert result.layer == "ascii_output"
        assert result.code is None
        assert result.details is not None
        assert result.details["row_count"] == 2

    def test_empty_result_set(self):
        """Empty result set should be valid."""
        result_set: list[dict[str, int]] = []

        result = validate_ascii_output(result_set, "test-002")
        assert result.success is True
        assert result.details is not None
        assert result.details["row_count"] == 0

    def test_null_values_allowed(self):
        """NULL values should be allowed in output."""
        result_set = [{"Count_Patients": 25000, "optional_field": None}]

        result = validate_ascii_output(result_set, "test-003")
        assert result.success is True

    def test_numeric_values(self):
        """Numeric values should pass validation."""
        result_set = [
            {"Count_Patients": 30000, "age": 45, "value": 123.456},
        ]

        result = validate_ascii_output(result_set, "test-004")
        assert result.success is True

    def test_allowed_ascii_characters(self):
        """All allowed ASCII characters should pass."""
        result_set = [
            {
                "Count_Patients": 25000,
                "description": "Test with space, tab\t, and newline\n!",
                "symbols": "!@#$%^&*()_+-=[]{}|;:',.<>?/~`",
            }
        ]

        result = validate_ascii_output(result_set, "test-005")
        assert result.success is True

    def test_carriage_return_allowed(self):
        """Carriage return should be allowed."""
        result_set = [{"Count_Patients": 25000, "text": "Line 1\r\nLine 2"}]

        result = validate_ascii_output(result_set, "test-006")
        assert result.success is True


class TestNonASCII:
    """Test non-ASCII character detection."""

    def test_unicode_character_blocked(self):
        """Unicode character should be blocked."""
        result_set = [{"Count_Patients": 25000, "description": "café"}]  # Unicode é (U+00E9)

        with pytest.raises(NonASCIIOutputError) as exc_info:
            validate_ascii_output(result_set, "test-101")

        assert exc_info.value.code == "E801"
        assert exc_info.value.details is not None
        assert exc_info.value.details["column"] == "description"
        assert exc_info.value.details["row_index"] == 0
        assert exc_info.value.details["char_code"] == 0xE9

    def test_emoji_blocked(self):
        """Emoji should be blocked."""
        result_set = [{"Count_Patients": 25000, "status": "complete ✓"}]  # Check mark

        with pytest.raises(NonASCIIOutputError) as exc_info:
            validate_ascii_output(result_set, "test-102")

        assert exc_info.value.code == "E801"

    def test_control_character_blocked(self):
        """Invalid control character should be blocked."""
        result_set = [{"Count_Patients": 25000, "data": "test\x00value"}]  # NULL byte

        with pytest.raises(NonASCIIOutputError) as exc_info:
            validate_ascii_output(result_set, "test-103")

        assert exc_info.value.code == "E801"
        assert exc_info.value.details is not None
        assert exc_info.value.details["char_code"] == 0x00

    def test_chinese_characters_blocked(self):
        """Chinese characters should be blocked."""
        result_set = [{"Count_Patients": 25000, "name": "测试"}]  # Chinese "test"

        with pytest.raises(NonASCIIOutputError):
            validate_ascii_output(result_set, "test-104")

    def test_cyrillic_characters_blocked(self):
        """Cyrillic characters should be blocked."""
        result_set = [{"Count_Patients": 25000, "text": "Москва"}]  # Moscow in Russian

        with pytest.raises(NonASCIIOutputError):
            validate_ascii_output(result_set, "test-105")

    def test_unicode_in_second_row(self):
        """Should detect Unicode in second row."""
        result_set = [
            {"Count_Patients": 25000, "text": "valid"},
            {"Count_Patients": 22000, "text": "invalid→"},  # Right arrow
        ]

        with pytest.raises(NonASCIIOutputError) as exc_info:
            validate_ascii_output(result_set, "test-106")

        assert exc_info.value.details is not None
        assert exc_info.value.details["row_index"] == 1

    def test_unicode_in_second_column(self):
        """Should detect Unicode in second column of row."""
        result_set = [
            {"Count_Patients": 25000, "col1": "valid", "col2": "café"},
        ]

        with pytest.raises(NonASCIIOutputError) as exc_info:
            validate_ascii_output(result_set, "test-107")

        assert exc_info.value.details is not None
        assert exc_info.value.details["column"] == "col2"


class TestPatientCountThreshold:
    """Test patient count threshold enforcement in results."""

    def test_count_above_threshold_passes(self):
        """Count above 20,000 should pass."""
        result_set = [{"Count_Patients": 25000}]

        result = validate_ascii_output(result_set, "test-201")
        assert result.success is True

    def test_count_exactly_at_threshold(self):
        """Count exactly at 20,000 should pass."""
        result_set = [{"Count_Patients": 20000}]

        result = validate_ascii_output(result_set, "test-202")
        assert result.success is True

    def test_count_below_threshold_fails(self):
        """Count below 20,000 should fail."""
        result_set = [{"Count_Patients": 15000}]

        with pytest.raises(PatientCountBelowThresholdError) as exc_info:
            validate_ascii_output(result_set, "test-203")

        assert exc_info.value.code == "E803"
        assert exc_info.value.details is not None
        assert exc_info.value.details["actual_count"] == 15000
        assert exc_info.value.details["min_count"] == 20000

    def test_count_just_below_threshold(self):
        """Count just below threshold should fail."""
        result_set = [{"Count_Patients": 19999}]

        with pytest.raises(PatientCountBelowThresholdError) as exc_info:
            validate_ascii_output(result_set, "test-204")

        assert exc_info.value.details is not None
        assert exc_info.value.details["actual_count"] == 19999

    def test_multiple_rows_all_above_threshold(self):
        """All rows with counts above threshold should pass."""
        result_set = [
            {"Count_Patients": 25000, "group": "A"},
            {"Count_Patients": 30000, "group": "B"},
            {"Count_Patients": 22000, "group": "C"},
        ]

        result = validate_ascii_output(result_set, "test-205")
        assert result.success is True

    def test_multiple_rows_one_below_threshold(self):
        """Should fail if any row is below threshold."""
        result_set = [
            {"Count_Patients": 25000, "group": "A"},
            {"Count_Patients": 15000, "group": "B"},  # Below threshold
            {"Count_Patients": 30000, "group": "C"},
        ]

        with pytest.raises(PatientCountBelowThresholdError):
            validate_ascii_output(result_set, "test-206")

    def test_custom_threshold(self):
        """Should respect custom threshold."""
        result_set = [{"Count_Patients": 15000}]

        # Should pass with lower threshold
        result = validate_ascii_output(result_set, "test-207", min_patient_count=10000)
        assert result.success is True

        # Should fail with higher threshold
        with pytest.raises(PatientCountBelowThresholdError):
            validate_ascii_output(result_set, "test-208", min_patient_count=20000)

    def test_float_patient_count(self):
        """Should handle float patient counts."""
        result_set = [{"Count_Patients": 25000.0}]

        result = validate_ascii_output(result_set, "test-209")
        assert result.success is True

    def test_no_count_patients_column(self):
        """Should not fail if Count_Patients column is missing."""
        result_set = [{"gender_concept_id": 8507, "value": 100}]

        result = validate_ascii_output(result_set, "test-210")
        assert result.success is True


class TestResultSizeLimit:
    """Test result set size limit enforcement."""

    def test_within_row_limit(self):
        """Result set within limit should pass."""
        result_set = [{"id": i, "Count_Patients": 25000} for i in range(100)]

        result = validate_ascii_output(result_set, "test-301")
        assert result.success is True

    def test_at_row_limit(self):
        """Result set exactly at limit should pass."""
        result_set = [{"id": i, "Count_Patients": 25000} for i in range(10000)]

        result = validate_ascii_output(result_set, "test-302")
        assert result.success is True

    def test_exceeds_row_limit(self):
        """Result set exceeding limit should fail."""
        result_set = [{"id": i} for i in range(15000)]

        with pytest.raises(TooManyRowsError) as exc_info:
            validate_ascii_output(result_set, "test-303", max_rows=10000)

        assert exc_info.value.code == "E805"
        assert exc_info.value.details is not None
        assert exc_info.value.details["row_count"] == 15000
        assert exc_info.value.details["max_rows"] == 10000

    def test_custom_max_rows(self):
        """Should respect custom max_rows."""
        result_set = [{"id": i} for i in range(500)]

        # Should pass with higher limit
        result = validate_ascii_output(result_set, "test-304", max_rows=1000)
        assert result.success is True

        # Should fail with lower limit
        with pytest.raises(TooManyRowsError):
            validate_ascii_output(result_set, "test-305", max_rows=100)


class TestPHIPatternWarnings:
    """Test PHI pattern detection (warnings, not errors)."""

    def test_date_pattern_generates_warning(self):
        """Date pattern should generate warning."""
        result_set = [{"Count_Patients": 25000, "date": "1985-06-15"}]

        result = validate_ascii_output(result_set, "test-401")
        assert result.success is True  # Should not fail
        assert result.details is not None
        assert len(result.details["warnings"]) > 0
        warning = result.details["warnings"][0]
        assert warning["pattern"] == "date_pattern"
        assert warning["column"] == "date"

    def test_email_pattern_generates_warning(self):
        """Email pattern should generate warning."""
        result_set = [{"Count_Patients": 25000, "contact": "user@example.com"}]

        result = validate_ascii_output(result_set, "test-402")
        assert result.success is True
        assert result.details is not None
        assert any(w["pattern"] == "email_pattern" for w in result.details["warnings"])

    def test_phone_pattern_generates_warning(self):
        """Phone pattern should generate warning."""
        result_set = [{"Count_Patients": 25000, "phone": "555-123-4567"}]

        result = validate_ascii_output(result_set, "test-403")
        assert result.success is True
        assert result.details is not None
        assert any(w["pattern"] == "phone_pattern" for w in result.details["warnings"])

    def test_ssn_pattern_generates_warning(self):
        """SSN pattern should generate warning."""
        result_set = [{"Count_Patients": 25000, "id": "123-45-6789"}]

        result = validate_ascii_output(result_set, "test-404")
        assert result.success is True
        assert result.details is not None
        assert any(w["pattern"] == "ssn_pattern" for w in result.details["warnings"])

    def test_zip_pattern_generates_warning(self):
        """ZIP code pattern should generate warning."""
        result_set = [{"Count_Patients": 25000, "zip": "12345"}]

        result = validate_ascii_output(result_set, "test-405")
        assert result.success is True
        assert result.details is not None
        assert any(w["pattern"] == "zip_pattern" for w in result.details["warnings"])

    def test_zip_plus_4_pattern(self):
        """ZIP+4 pattern should generate warning."""
        result_set = [{"Count_Patients": 25000, "zip": "12345-6789"}]

        result = validate_ascii_output(result_set, "test-406")
        assert result.success is True
        assert result.details is not None
        assert any(w["pattern"] == "zip_pattern" for w in result.details["warnings"])

    def test_multiple_patterns_in_result(self):
        """Multiple PHI patterns should generate multiple warnings."""
        result_set = [{"Count_Patients": 25000, "date": "1985-06-15", "email": "user@example.com"}]

        result = validate_ascii_output(result_set, "test-407")
        assert result.success is True
        assert result.details is not None
        assert len(result.details["warnings"]) >= 2

    def test_no_false_positives(self):
        """Normal values should not trigger warnings."""
        result_set = [
            {
                "Count_Patients": 25000,
                "gender_concept_id": 8507,
                "description": "Male patients",
            }
        ]

        result = validate_ascii_output(result_set, "test-408")
        assert result.success is True
        assert result.details is not None
        assert len(result.details["warnings"]) == 0


class TestPHIPatternHelpers:
    """Test PHI pattern detection helper functions."""

    def test_check_phi_patterns_date(self):
        """Date pattern should be detected."""
        assert _check_phi_patterns("1985-06-15") == "date_pattern"
        assert _check_phi_patterns("2023-12-31") == "date_pattern"

    def test_check_phi_patterns_email(self):
        """Email pattern should be detected."""
        assert _check_phi_patterns("user@example.com") == "email_pattern"
        assert _check_phi_patterns("test.user@domain.org") == "email_pattern"

    def test_check_phi_patterns_phone(self):
        """Phone pattern should be detected."""
        assert _check_phi_patterns("555-123-4567") == "phone_pattern"

    def test_check_phi_patterns_ssn(self):
        """SSN pattern should be detected."""
        assert _check_phi_patterns("123-45-6789") == "ssn_pattern"

    def test_check_phi_patterns_zip(self):
        """ZIP pattern should be detected."""
        assert _check_phi_patterns("12345") == "zip_pattern"
        assert _check_phi_patterns("12345-6789") == "zip_pattern"

    def test_check_phi_patterns_no_match(self):
        """Non-PHI values should return empty string."""
        assert _check_phi_patterns("hello world") == ""
        assert _check_phi_patterns("12345678") == ""  # Not a ZIP (too long)
        assert _check_phi_patterns("test") == ""


class TestSafePreview:
    """Test safe preview generation for logging."""

    def test_empty_result_preview(self):
        """Empty result set should have safe preview."""
        preview = get_safe_preview([])
        assert "Empty result set" in preview

    def test_single_row_preview(self):
        """Single row should be previewed."""
        result_set = [{"Count_Patients": 25000, "gender": "M"}]
        preview = get_safe_preview(result_set)
        assert "1 total rows" in preview
        assert "Count_Patients" in preview
        assert "gender" in preview

    def test_multiple_rows_preview(self):
        """Multiple rows should be previewed with limit."""
        result_set = [{"id": i, "value": i * 10} for i in range(20)]
        preview = get_safe_preview(result_set, max_rows=5)
        assert "20 total rows" in preview
        assert "... and 15 more rows" in preview

    def test_preview_truncates_long_values(self):
        """Long values should be truncated."""
        result_set = [{"data": "x" * 200}]
        preview = get_safe_preview(result_set)
        assert len(preview) < 500  # Should be truncated


class TestPerformance:
    """Performance tests for output validation."""

    def test_validation_performance_1000_rows(self):
        """Validation should be fast for 1000 rows."""
        import time

        result_set = [{"Count_Patients": 25000, "id": i, "value": f"test_{i}"} for i in range(1000)]

        start = time.perf_counter()
        validate_ascii_output(result_set, "test-501")
        duration = (time.perf_counter() - start) * 1000

        # Should complete in <50ms (realistic threshold)
        assert duration < 50

    def test_validation_performance_large_strings(self):
        """Validation should handle large strings efficiently."""
        import time

        result_set = [{"Count_Patients": 25000, "description": "x" * 1000} for _ in range(100)]

        start = time.perf_counter()
        validate_ascii_output(result_set, "test-502")
        duration = (time.perf_counter() - start) * 1000

        # Should complete in reasonable time (<50ms)
        assert duration < 50


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_boolean_values(self):
        """Boolean values should pass validation."""
        result_set = [{"Count_Patients": 25000, "is_active": True, "is_deleted": False}]

        result = validate_ascii_output(result_set, "test-601")
        assert result.success is True

    def test_mixed_types(self):
        """Mixed data types should pass validation."""
        result_set = [
            {
                "Count_Patients": 25000,
                "int_val": 42,
                "float_val": 3.14,
                "str_val": "test",
                "bool_val": True,
                "null_val": None,
            }
        ]

        result = validate_ascii_output(result_set, "test-602")
        assert result.success is True

    def test_zero_patient_count(self):
        """Zero patient count should fail."""
        result_set = [{"Count_Patients": 0}]

        with pytest.raises(PatientCountBelowThresholdError):
            validate_ascii_output(result_set, "test-603")

    def test_negative_patient_count(self):
        """Negative patient count should fail."""
        result_set = [{"Count_Patients": -100}]

        with pytest.raises(PatientCountBelowThresholdError):
            validate_ascii_output(result_set, "test-604")

    def test_very_large_patient_count(self):
        """Very large patient count should pass."""
        result_set = [{"Count_Patients": 1000000000}]

        result = validate_ascii_output(result_set, "test-605")
        assert result.success is True

    def test_single_character_values(self):
        """Single character values should pass."""
        result_set = [{"Count_Patients": 25000, "code": "A"}]

        result = validate_ascii_output(result_set, "test-606")
        assert result.success is True

    def test_empty_string_values(self):
        """Empty string values should pass."""
        result_set = [{"Count_Patients": 25000, "note": ""}]

        result = validate_ascii_output(result_set, "test-607")
        assert result.success is True

    def test_whitespace_only_values(self):
        """Whitespace-only values should pass."""
        result_set = [{"Count_Patients": 25000, "note": "   "}]

        result = validate_ascii_output(result_set, "test-608")
        assert result.success is True
