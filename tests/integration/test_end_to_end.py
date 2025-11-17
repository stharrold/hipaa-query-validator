"""Integration tests for end-to-end validation workflows.

Tests validate complete query validation pipeline through all layers.
"""

import uuid

import pytest

from src.educational import format_educational_response, get_educational_guidance
from src.enforcer import validate_no_circumvention, wrap_query
from src.errors import (
    DirectPHIIdentifierError,
    EmptyQueryError,
    InvalidPatientCountSyntaxError,
    MissingGroupByError,
    NonASCIICharacterError,
    SelectStarError,
    SubqueryNotAllowedError,
)
from src.validators.aggregation import validate_aggregation
from src.validators.ascii_input import validate_ascii_input
from src.validators.phi import validate_phi
from src.validators.sample_execution import validate_sample_execution


def generate_request_id() -> str:
    """Generate unique request ID for testing."""
    return f"test-{uuid.uuid4().hex[:8]}"


class TestValidQueryEndToEnd:
    """Tests for valid queries passing through all validation layers."""

    def test_simple_valid_query(self):
        """Test simple valid query through all layers."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """

        request_id = generate_request_id()

        # Layer 0: ASCII validation
        result_0 = validate_ascii_input(query, request_id)
        assert result_0.success is True

        # Layer 2: PHI validation
        result_2 = validate_phi(query, request_id)
        assert result_2.success is True

        # Layer 3: Aggregation validation
        result_3 = validate_aggregation(query, request_id)
        assert result_3.success is True

        # Layer 4: Enforcement validation
        result_4 = validate_no_circumvention(query, request_id)
        assert result_4.success is True

        # Wrap query with enforcement
        wrapped = wrap_query(query)
        assert "WHERE Count_Patients >= 20000" in wrapped

        # Layer 5: Sample execution validation
        result_5 = validate_sample_execution(wrapped, request_id)
        assert result_5.success is True
        assert result_5.layer == "sample_execution"
        assert result_5.details is not None
        assert result_5.details["status"] == "executed"

    def test_complex_valid_query(self):
        """Test complex query with multiple dimensions."""
        query = """
        SELECT p.gender_concept_id,
               p.race_concept_id,
               p.year_of_birth,
               COUNT(DISTINCT p.person_id) AS Count_Patients,
               AVG(CAST(p.year_of_birth AS FLOAT)) AS Avg_Birth_Year
        FROM person p
        JOIN condition_occurrence co ON p.person_id = co.person_id
        WHERE p.gender_concept_id IN (8507, 8532)
        GROUP BY p.gender_concept_id, p.race_concept_id, p.year_of_birth
        """

        request_id = generate_request_id()

        # All layers should pass
        assert validate_ascii_input(query, request_id).success is True
        assert validate_phi(query, request_id).success is True
        assert validate_aggregation(query, request_id).success is True
        assert validate_no_circumvention(query, request_id).success is True

        # Layer 5: Sample execution
        wrapped = wrap_query(query)
        assert validate_sample_execution(wrapped, request_id).success is True

    def test_global_aggregate_valid(self):
        """Test global aggregate query (no GROUP BY needed)."""
        query = """
        SELECT COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        """

        request_id = generate_request_id()

        assert validate_ascii_input(query, request_id).success is True
        assert validate_phi(query, request_id).success is True
        assert validate_aggregation(query, request_id).success is True
        assert validate_no_circumvention(query, request_id).success is True

        # Layer 5: Sample execution
        wrapped = wrap_query(query)
        assert validate_sample_execution(wrapped, request_id).success is True


class TestLayer0Failures:
    """Tests for queries failing at Layer 0 (ASCII validation)."""

    def test_unicode_character_rejection(self):
        """Test rejection at Layer 0 for Unicode character."""
        query = "SELECT * FROM café"
        request_id = generate_request_id()

        with pytest.raises(NonASCIICharacterError) as exc_info:
            validate_ascii_input(query, request_id)

        error = exc_info.value
        assert error.code == "E001"
        assert error.layer == "ascii_input"

        # Test educational response
        guidance, pattern = get_educational_guidance("E001")
        assert "non-ascii" in guidance.lower()  # Check lowercase after calling .lower()
        assert "SQL injection" in guidance or "sql injection" in guidance.lower()

    def test_empty_query_rejection(self):
        """Test rejection of empty query."""
        query = "   \n\t  "
        request_id = generate_request_id()

        with pytest.raises(EmptyQueryError) as exc_info:
            validate_ascii_input(query, request_id)

        assert exc_info.value.code == "E003"


class TestLayer2Failures:
    """Tests for queries failing at Layer 2 (PHI validation)."""

    def test_select_star_rejection(self):
        """Test rejection at Layer 2 for SELECT *."""
        query = "SELECT * FROM person"
        request_id = generate_request_id()

        # Layer 0 passes
        assert validate_ascii_input(query, request_id).success is True

        # Layer 2 fails
        with pytest.raises(SelectStarError) as exc_info:
            validate_phi(query, request_id)

        error = exc_info.value
        assert error.code == "E204"

        # Test educational response
        response = format_educational_response(error.code, error.message, error.details)
        assert "explicit" in response["educational_guidance"].lower()
        assert "SELECT" in response["correct_pattern"]

    def test_phi_column_rejection(self):
        """Test rejection at Layer 2 for PHI column."""
        query = """
        SELECT patient_name,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY patient_name
        """
        request_id = generate_request_id()

        # Layer 0 passes
        assert validate_ascii_input(query, request_id).success is True

        # Layer 2 fails
        with pytest.raises(DirectPHIIdentifierError) as exc_info:
            validate_phi(query, request_id)

        error = exc_info.value
        assert error.code == "E201"
        assert "patient_name" in error.details["column_name"].lower()

        # Test educational response
        guidance, pattern = get_educational_guidance("E201")
        assert "18 HIPAA identifiers" in guidance


class TestLayer3Failures:
    """Tests for queries failing at Layer 3 (Aggregation validation)."""

    def test_missing_group_by_rejection(self):
        """Test rejection at Layer 3 for missing GROUP BY."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        """
        request_id = generate_request_id()

        # Layers 0, 2 pass
        assert validate_ascii_input(query, request_id).success is True
        assert validate_phi(query, request_id).success is True

        # Layer 3 fails
        with pytest.raises(MissingGroupByError) as exc_info:
            validate_aggregation(query, request_id)

        error = exc_info.value
        assert error.code == "E301"

        guidance, pattern = get_educational_guidance("E301")
        assert "GROUP BY" in pattern

    def test_invalid_patient_count_syntax_rejection(self):
        """Test rejection for incorrect patient count syntax."""
        query = """
        SELECT gender_concept_id,
               COUNT(person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """
        request_id = generate_request_id()

        # Layers 0, 2 pass
        assert validate_ascii_input(query, request_id).success is True
        assert validate_phi(query, request_id).success is True

        # Layer 3 fails
        with pytest.raises(InvalidPatientCountSyntaxError) as exc_info:
            validate_aggregation(query, request_id)

        error = exc_info.value
        assert error.code == "E303"
        assert "DISTINCT" in error.message


class TestLayer4Failures:
    """Tests for queries failing at Layer 4 (Enforcement validation)."""

    def test_subquery_rejection(self):
        """Test rejection at Layer 4 for subquery."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM (
            SELECT * FROM person WHERE year_of_birth > 1980
        ) AS subq
        GROUP BY gender_concept_id
        """
        request_id = generate_request_id()

        # Layers 0, 2, 3 may pass individual checks
        # Layer 4 fails
        with pytest.raises(SubqueryNotAllowedError) as exc_info:
            validate_no_circumvention(query, request_id)

        error = exc_info.value
        assert error.code == "E401"

        guidance, _ = get_educational_guidance("E401")
        assert "circumvent" in guidance.lower()


class TestEducationalResponses:
    """Tests for educational response system."""

    def test_all_error_codes_have_guidance(self):
        """Test that all implemented error codes have educational guidance."""
        error_codes = [
            "E001",
            "E002",
            "E003",
            "E201",
            "E202",
            "E203",
            "E204",
            "E301",
            "E302",
            "E303",
            "E401",
            "E402",
        ]

        for code in error_codes:
            guidance, pattern = get_educational_guidance(code)
            assert guidance is not None
            assert len(guidance) > 0
            # Some codes may not have patterns (system errors)
            if code not in ["E801", "E802"]:
                assert pattern is not None or "Unknown" in guidance

    def test_educational_response_format(self):
        """Test format of educational responses."""
        response = format_educational_response(
            "E201", "Direct PHI identifier detected", {"column_name": "patient_name"}
        )

        assert "error_code" in response
        assert "message" in response
        assert "educational_guidance" in response
        assert "documentation" in response
        assert response["error_code"] == "E201"


class TestQueryWrapping:
    """Tests for SQL enforcement wrapper."""

    def test_wrap_simple_query(self):
        """Test wrapping a simple valid query."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """

        wrapped = wrap_query(query)

        assert "SELECT * FROM (" in wrapped
        assert ") AS validated_query" in wrapped
        assert "WHERE Count_Patients >= 20000" in wrapped
        assert query.strip() in wrapped

    def test_wrap_complex_query(self):
        """Test wrapping a complex query."""
        query = """
        SELECT p.gender_concept_id,
               p.race_concept_id,
               COUNT(DISTINCT p.person_id) AS Count_Patients
        FROM person p
        JOIN condition_occurrence co ON p.person_id = co.person_id
        WHERE p.year_of_birth > 1950
        GROUP BY p.gender_concept_id, p.race_concept_id
        """

        wrapped = wrap_query(query)

        # Verify wrapper structure
        assert wrapped.count("SELECT") >= 2  # Original + wrapper
        assert "validated_query" in wrapped
        assert "Count_Patients >= 20000" in wrapped


class TestPerformance:
    """Tests for validation performance requirements."""

    def test_validation_performance(self):
        """Test that validation completes within performance target (<10ms)."""
        import time

        query = """
        SELECT gender_concept_id,
               race_concept_id,
               year_of_birth,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id, race_concept_id, year_of_birth
        """

        request_id = generate_request_id()

        # Time all validation layers
        start = time.time()

        validate_ascii_input(query, request_id)
        validate_phi(query, request_id)
        validate_aggregation(query, request_id)
        validate_no_circumvention(query, request_id)

        end = time.time()
        elapsed_ms = (end - start) * 1000

        # Performance target: <10ms (p95)
        # For single query, should be well under this
        assert elapsed_ms < 50  # Allow some margin for test environment


class TestRealWorldQueries:
    """Tests with realistic healthcare queries."""

    def test_condition_prevalence_query(self):
        """Test query for condition prevalence by gender."""
        query = """
        SELECT p.gender_concept_id,
               co.condition_concept_id,
               COUNT(DISTINCT p.person_id) AS Count_Patients
        FROM person p
        INNER JOIN condition_occurrence co ON p.person_id = co.person_id
        WHERE co.condition_concept_id = 201826
        GROUP BY p.gender_concept_id, co.condition_concept_id
        """

        request_id = generate_request_id()

        assert validate_ascii_input(query, request_id).success is True
        assert validate_phi(query, request_id).success is True
        assert validate_aggregation(query, request_id).success is True
        assert validate_no_circumvention(query, request_id).success is True

    def test_demographic_distribution_query(self):
        """Test query for demographic distribution."""
        query = """
        SELECT gender_concept_id,
               race_concept_id,
               ethnicity_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id, race_concept_id, ethnicity_concept_id
        """

        request_id = generate_request_id()

        assert validate_ascii_input(query, request_id).success is True
        assert validate_phi(query, request_id).success is True
        assert validate_aggregation(query, request_id).success is True
        assert validate_no_circumvention(query, request_id).success is True
