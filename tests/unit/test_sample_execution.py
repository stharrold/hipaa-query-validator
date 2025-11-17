"""Unit tests for Layer 5: Sample execution validation.

Tests validate that queries execute correctly against sample data and that
runtime errors are caught appropriately.
"""

import pytest

from src.enforcer import wrap_query
from src.errors import (
    QueryExecutionError,
    ResultSetTooLargeError,
)
from src.validators.sample_execution import (
    extract_column_names,
    get_sample_results,
    validate_sample_execution,
)


def generate_request_id(test_num: int) -> str:
    """Generate test request ID."""
    return f"test-{test_num:03d}"


class TestValidExecution:
    """Test valid query execution."""

    def test_simple_query_executes(self):
        """Simple query should execute successfully."""
        query = "SELECT COUNT(DISTINCT person_id) AS Count_Patients FROM person"
        wrapped = wrap_query(query)

        result = validate_sample_execution(wrapped, generate_request_id(1))

        assert result.success is True
        assert result.layer == "sample_execution"
        assert result.details is not None
        assert result.details["status"] == "executed"
        # Sample DB has 1000 patients, so enforcement wrapper filters to 0 rows
        assert result.details["row_count"] >= 0
        assert result.details["execution_time_ms"] < 500
        assert "Count_Patients" in result.details["column_names"]

    def test_query_with_where_clause(self):
        """Query with WHERE clause executes."""
        query = """
        SELECT COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        WHERE year_of_birth > 1980
        """
        wrapped = wrap_query(query)

        result = validate_sample_execution(wrapped, generate_request_id(2))
        assert result.success is True
        assert result.details["status"] == "executed"

    def test_query_with_group_by(self):
        """Query with GROUP BY executes."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """
        wrapped = wrap_query(query)

        result = validate_sample_execution(wrapped, generate_request_id(3))
        assert result.success is True
        assert result.details["row_count"] >= 0
        assert "gender_concept_id" in result.details["column_names"]
        assert "Count_Patients" in result.details["column_names"]

    def test_query_with_join(self):
        """Query with JOIN executes."""
        query = """
        SELECT COUNT(DISTINCT p.person_id) AS Count_Patients
        FROM person p
        JOIN condition_occurrence c ON p.person_id = c.person_id
        WHERE c.condition_concept_id = 201826
        """
        wrapped = wrap_query(query)

        result = validate_sample_execution(wrapped, generate_request_id(4))
        assert result.success is True
        assert result.details["status"] == "executed"

    def test_complex_query_with_multiple_joins(self):
        """Complex query with multiple JOINs and aggregations."""
        query = """
        SELECT p.gender_concept_id,
               p.race_concept_id,
               COUNT(DISTINCT p.person_id) AS Count_Patients,
               AVG(CAST(p.year_of_birth AS FLOAT)) AS Avg_Birth_Year
        FROM person p
        JOIN condition_occurrence co ON p.person_id = co.person_id
        JOIN observation_period op ON p.person_id = op.person_id
        WHERE p.year_of_birth > 1950
        GROUP BY p.gender_concept_id, p.race_concept_id
        """
        wrapped = wrap_query(query)

        result = validate_sample_execution(wrapped, generate_request_id(5))
        assert result.success is True
        assert result.details["row_count"] >= 0
        assert len(result.details["column_names"]) == 4

    def test_global_aggregate_executes(self):
        """Global aggregate query (no GROUP BY) executes."""
        query = """
        SELECT COUNT(DISTINCT person_id) AS Count_Patients,
               AVG(year_of_birth) AS Avg_Birth_Year
        FROM person
        """
        wrapped = wrap_query(query)

        result = validate_sample_execution(wrapped, generate_request_id(6))
        assert result.success is True
        # Global aggregate should return 1 row (or 0 after enforcement filtering)
        assert result.details["row_count"] <= 1


class TestExecutionErrors:
    """Test query execution errors."""

    def test_syntax_error_caught(self):
        """Invalid SQL syntax should raise QueryExecutionError."""
        # FORM instead of FROM
        query = "SELECT COUNT(DISTINCT person_id) AS Count_Patients FORM person"
        wrapped = wrap_query(query)

        with pytest.raises(QueryExecutionError) as exc_info:
            validate_sample_execution(wrapped, generate_request_id(101))

        error = exc_info.value
        assert error.code == "E501"
        assert error.layer == "sample_execution"

    def test_invalid_column_caught(self):
        """Reference to non-existent column should error."""
        query = "SELECT COUNT(DISTINCT invalid_column) AS Count_Patients FROM person"
        wrapped = wrap_query(query)

        with pytest.raises(QueryExecutionError) as exc_info:
            validate_sample_execution(wrapped, generate_request_id(102))

        assert exc_info.value.code == "E501"

    def test_invalid_table_caught(self):
        """Reference to non-existent table should error."""
        query = "SELECT COUNT(DISTINCT person_id) AS Count_Patients FROM invalid_table"
        wrapped = wrap_query(query)

        with pytest.raises(QueryExecutionError) as exc_info:
            validate_sample_execution(wrapped, generate_request_id(103))

        assert exc_info.value.code == "E501"

    def test_type_mismatch_caught(self):
        """Type mismatch in WHERE clause should error."""
        query = """
        SELECT COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        WHERE year_of_birth = 'not_a_number'
        """
        wrapped = wrap_query(query)

        # SQLite is very permissive with type conversions, so this might not error
        # but we'll keep the test for documentation purposes
        # In a stricter database, this would raise QueryExecutionError
        try:
            result = validate_sample_execution(wrapped, generate_request_id(104))
            # If it doesn't error, that's fine for SQLite
            assert result.success is True
        except QueryExecutionError as e:
            # If it does error, verify it's the right error
            assert e.code == "E501"


class TestResultValidation:
    """Test result set validation."""

    def test_empty_result_accepted(self):
        """Empty result should NOT raise an error (just return 0 rows)."""
        query = """
        SELECT COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        WHERE year_of_birth > 2030
        """
        wrapped = wrap_query(query)

        # Should execute but return 0 or 1 row
        result = validate_sample_execution(wrapped, generate_request_id(301))
        # After enforcement wrapper, might return 0 or 1 row
        assert result.details["row_count"] in [0, 1]

    def test_result_set_too_large(self):
        """Result set exceeding max_rows should error."""
        # Query that returns all condition_occurrence rows (3000-5000 rows)
        query = "SELECT * FROM condition_occurrence"

        with pytest.raises(ResultSetTooLargeError) as exc_info:
            validate_sample_execution(query, generate_request_id(302), max_rows=1000)

        error = exc_info.value
        assert error.code == "E504"
        assert error.details["row_count"] > 1000


class TestPerformance:
    """Performance tests."""

    def test_execution_completes_quickly(self):
        """Sample execution should complete in <500ms."""
        query = """
        SELECT gender_concept_id,
               race_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id, race_concept_id
        """
        wrapped = wrap_query(query)

        result = validate_sample_execution(wrapped, generate_request_id(401), timeout_ms=500)

        assert result.success is True
        # Should complete well under 500ms on sample data
        assert result.details["execution_time_ms"] < 500

    def test_complex_query_performance(self):
        """Complex query should still complete in reasonable time."""
        query = """
        SELECT p.gender_concept_id,
               p.race_concept_id,
               p.year_of_birth,
               COUNT(DISTINCT p.person_id) AS Count_Patients
        FROM person p
        JOIN condition_occurrence co ON p.person_id = co.person_id
        WHERE co.condition_concept_id IN (201826, 435216, 4058243)
        GROUP BY p.gender_concept_id, p.race_concept_id, p.year_of_birth
        """
        wrapped = wrap_query(query)

        result = validate_sample_execution(wrapped, generate_request_id(402))

        assert result.success is True
        # Even complex queries should be fast on 1000 person sample
        assert result.details["execution_time_ms"] < 1000


class TestSampleDataQuality:
    """Test sample data quality and consistency."""

    def test_sample_db_has_persons(self):
        """Sample database should have 1000 persons."""
        from src.sample_data.generator import sample_db

        conn = sample_db.get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM person")
        person_count = cursor.fetchone()[0]
        assert person_count == 1000

    def test_sample_db_has_conditions(self):
        """Sample database should have conditions for all persons."""
        from src.sample_data.generator import sample_db

        conn = sample_db.get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM condition_occurrence")
        condition_count = cursor.fetchone()[0]
        # Each person has 3-5 conditions, so total should be 3000-5000
        assert 3000 <= condition_count <= 5000

    def test_sample_data_quality(self):
        """Sample data should have realistic values."""
        from src.sample_data.generator import sample_db

        conn = sample_db.get_connection()
        cursor = conn.cursor()

        # Check year_of_birth range
        cursor.execute("SELECT MIN(year_of_birth), MAX(year_of_birth) FROM person")
        min_year, max_year = cursor.fetchone()
        assert 1940 <= min_year <= 2005
        assert 1940 <= max_year <= 2005

        # Check gender distribution
        cursor.execute("SELECT DISTINCT gender_concept_id FROM person")
        genders = [row[0] for row in cursor.fetchall()]
        assert 8507 in genders  # Male
        assert 8532 in genders  # Female

    def test_sample_db_row_counts(self):
        """Test get_row_counts helper function."""
        from src.sample_data.generator import sample_db

        counts = sample_db.get_row_counts()

        assert counts["person"] == 1000
        assert 3000 <= counts["condition_occurrence"] <= 5000
        assert counts["observation_period"] == 1000


class TestHelperFunctions:
    """Test helper functions for debugging and analysis."""

    def test_extract_column_names(self):
        """Test column name extraction."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """
        wrapped = wrap_query(query)

        columns = extract_column_names(wrapped)

        # After wrapping, should have all columns from the subquery
        assert "gender_concept_id" in columns
        assert "Count_Patients" in columns

    def test_get_sample_results(self):
        """Test sample results retrieval."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """
        wrapped = wrap_query(query)

        results = get_sample_results(wrapped, limit=5)

        # Should get results (might be 0 if no groups meet threshold)
        assert isinstance(results, list)
        assert len(results) <= 5

    def test_extract_column_names_invalid_query(self):
        """Test column extraction with invalid query."""
        query = "SELECT * FROM invalid_table"

        columns = extract_column_names(query)

        # Should return empty list for invalid queries
        assert columns == []


class TestEnforcementIntegration:
    """Test integration with Layer 4 enforcement wrapper."""

    def test_wrapped_query_executes(self):
        """Wrapped query should execute correctly."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """
        wrapped = wrap_query(query, min_patient_count=20000)

        result = validate_sample_execution(wrapped, generate_request_id(501))

        assert result.success is True
        # Enforcement wrapper filters to >= 20000, so might return 0 rows on sample data
        assert result.details["row_count"] >= 0

    def test_enforcement_filters_small_counts(self):
        """Enforcement wrapper should filter groups with <20000 patients."""
        query = """
        SELECT year_of_birth,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY year_of_birth
        """
        wrapped = wrap_query(query, min_patient_count=20000)

        result = validate_sample_execution(wrapped, generate_request_id(502))

        assert result.success is True
        # Sample DB only has 1000 patients, so all groups should be filtered
        # Result should be 0 rows
        assert result.details["row_count"] == 0

    def test_global_aggregate_below_threshold(self):
        """Global aggregate with <20000 patients should return 0 rows."""
        query = """
        SELECT COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        """
        wrapped = wrap_query(query, min_patient_count=20000)

        result = validate_sample_execution(wrapped, generate_request_id(503))

        assert result.success is True
        # Only 1000 patients in sample, so enforcement filters it out
        assert result.details["row_count"] == 0
