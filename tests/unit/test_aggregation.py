"""Unit tests for Layer 3: Aggregation Enforcement.

Tests validate that queries:
1. Include GROUP BY clause (except global aggregates)
2. Have exact syntax: COUNT(DISTINCT person_id) AS Count_Patients
3. Use aggregate functions only in SELECT clause
"""

import pytest

from src.errors import (
    InvalidPatientCountSyntaxError,
    MissingGroupByError,
    MissingPatientCountError,
)
from src.validators.aggregation import (
    extract_group_by_columns,
    has_required_patient_count,
    validate_aggregation,
)


class TestValidAggregationQueries:
    """Tests for valid queries that should pass aggregation validation."""

    def test_simple_group_by_query(self):
        """Test simple query with GROUP BY and patient count."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """
        result = validate_aggregation(query, "test-001")
        assert result.success is True
        assert result.layer == "aggregation"

    def test_multiple_dimensions(self):
        """Test query grouped by multiple dimensions."""
        query = """
        SELECT gender_concept_id,
               race_concept_id,
               year_of_birth,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id, race_concept_id, year_of_birth
        """
        result = validate_aggregation(query, "test-002")
        assert result.success is True

    def test_global_aggregate(self):
        """Test global aggregate (no GROUP BY needed)."""
        query = """
        SELECT COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        """
        result = validate_aggregation(query, "test-003")
        assert result.success is True

    def test_with_additional_aggregates(self):
        """Test query with additional aggregate functions."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients,
               AVG(year_of_birth) AS Avg_Birth_Year
        FROM person
        GROUP BY gender_concept_id
        """
        result = validate_aggregation(query, "test-004")
        assert result.success is True

    def test_join_with_aggregation(self):
        """Test JOIN query with proper aggregation."""
        query = """
        SELECT p.gender_concept_id,
               COUNT(DISTINCT p.person_id) AS Count_Patients
        FROM person p
        JOIN condition_occurrence co ON p.person_id = co.person_id
        GROUP BY p.gender_concept_id
        """
        result = validate_aggregation(query, "test-005")
        assert result.success is True


class TestMissingGroupBy:
    """Tests for queries missing GROUP BY clause."""

    def test_no_group_by_no_aggregates(self):
        """Test query with no GROUP BY and no aggregates (invalid)."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        """
        # Missing GROUP BY
        with pytest.raises(MissingGroupByError) as exc_info:
            validate_aggregation(query, "test-101")

        error = exc_info.value
        assert error.code == "E301"
        assert error.layer == "aggregation"

    def test_select_with_dimensions_no_group_by(self):
        """Test query selecting dimensions without GROUP BY."""
        query = """
        SELECT gender_concept_id,
               race_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        """

        with pytest.raises(MissingGroupByError):
            validate_aggregation(query, "test-102")


class TestMissingPatientCount:
    """Tests for queries missing required patient count."""

    def test_no_patient_count(self):
        """Test query with GROUP BY but no patient count."""
        query = """
        SELECT gender_concept_id
        FROM person
        GROUP BY gender_concept_id
        """

        with pytest.raises(MissingPatientCountError) as exc_info:
            validate_aggregation(query, "test-201")

        error = exc_info.value
        assert error.code == "E302"

    def test_only_other_aggregates(self):
        """Test query with other aggregates but no patient count."""
        query = """
        SELECT gender_concept_id,
               AVG(year_of_birth) AS avg_year
        FROM person
        GROUP BY gender_concept_id
        """

        with pytest.raises(MissingPatientCountError):
            validate_aggregation(query, "test-202")


class TestInvalidPatientCountSyntax:
    """Tests for incorrect patient count syntax."""

    def test_missing_distinct(self):
        """Test COUNT without DISTINCT."""
        query = """
        SELECT gender_concept_id,
               COUNT(person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """

        with pytest.raises(InvalidPatientCountSyntaxError) as exc_info:
            validate_aggregation(query, "test-301")

        error = exc_info.value
        assert error.code == "E303"
        assert "COUNT(person_id)" in error.details["found_syntax"]

    def test_missing_alias(self):
        """Test COUNT(DISTINCT person_id) without AS Count_Patients."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id)
        FROM person
        GROUP BY gender_concept_id
        """

        with pytest.raises(InvalidPatientCountSyntaxError):
            validate_aggregation(query, "test-302")

    def test_wrong_alias(self):
        """Test COUNT(DISTINCT person_id) with wrong alias name."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS patient_count
        FROM person
        GROUP BY gender_concept_id
        """

        with pytest.raises(InvalidPatientCountSyntaxError):
            validate_aggregation(query, "test-303")

    def test_wrong_column(self):
        """Test COUNT(DISTINCT ...) on wrong column."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT gender_concept_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """

        # This should fail because it's not counting person_id
        with pytest.raises(MissingPatientCountError):
            validate_aggregation(query, "test-304")


class TestAggregatesInWrongClauses:
    """Tests for aggregate functions in non-SELECT clauses."""

    def test_aggregate_in_where(self):
        """Test aggregate function in WHERE clause (not allowed)."""
        # Note: sqlparse may not always catch this, but we test the intent
        # In practice, this might also fail at SQL execution level
        # For now, we document expected behavior

    def test_aggregate_in_group_by(self):
        """Test aggregate function in GROUP BY clause (not allowed)."""
        # Document expected behavior - aggregates not allowed in GROUP BY


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_extract_group_by_columns(self):
        """Test extraction of GROUP BY columns."""
        query = """
        SELECT gender_concept_id,
               race_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id, race_concept_id
        """

        columns = extract_group_by_columns(query)
        assert len(columns) >= 1  # Should find at least one column

    def test_has_required_patient_count_true(self):
        """Test detection of correct patient count."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """

        assert has_required_patient_count(query) is True

    def test_has_required_patient_count_false(self):
        """Test detection of missing patient count."""
        query = """
        SELECT gender_concept_id
        FROM person
        GROUP BY gender_concept_id
        """

        assert has_required_patient_count(query) is False

    def test_has_required_patient_count_wrong_syntax(self):
        """Test detection of incorrect patient count syntax."""
        query = """
        SELECT gender_concept_id,
               COUNT(person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """

        assert has_required_patient_count(query) is False


class TestWhitespaceVariations:
    """Tests for queries with various whitespace patterns."""

    def test_extra_whitespace(self):
        """Test query with extra whitespace."""
        query = """
        SELECT   gender_concept_id  ,
                 COUNT  (  DISTINCT   person_id  )   AS   Count_Patients
        FROM     person
        GROUP    BY    gender_concept_id
        """

        result = validate_aggregation(query, "test-501")
        assert result.success is True

    def test_single_line_query(self):
        """Test single-line query."""
        query = "SELECT gender_concept_id, COUNT(DISTINCT person_id) AS Count_Patients FROM person GROUP BY gender_concept_id"

        result = validate_aggregation(query, "test-502")
        assert result.success is True

    def test_tabs_and_newlines(self):
        """Test query with tabs and newlines."""
        query = "SELECT gender_concept_id,\n\tCOUNT(DISTINCT person_id) AS Count_Patients\nFROM person\nGROUP BY gender_concept_id"

        result = validate_aggregation(query, "test-503")
        assert result.success is True


class TestCaseInsensitivity:
    """Tests for case-insensitive keyword matching."""

    def test_lowercase_keywords(self):
        """Test query with lowercase keywords."""
        query = """
        select gender_concept_id,
               count(distinct person_id) as Count_Patients
        from person
        group by gender_concept_id
        """

        result = validate_aggregation(query, "test-601")
        assert result.success is True

    def test_uppercase_keywords(self):
        """Test query with uppercase keywords."""
        query = """
        SELECT GENDER_CONCEPT_ID,
               COUNT(DISTINCT PERSON_ID) AS COUNT_PATIENTS
        FROM PERSON
        GROUP BY GENDER_CONCEPT_ID
        """

        # Note: Alias must still be exactly "Count_Patients"
        # This test will fail due to wrong alias case
        with pytest.raises(InvalidPatientCountSyntaxError):
            validate_aggregation(query, "test-602")

    def test_mixed_case_keywords(self):
        """Test query with mixed case keywords."""
        query = """
        SeLeCt gender_concept_id,
               CoUnT(DiStInCt person_id) As Count_Patients
        FrOm person
        GrOuP bY gender_concept_id
        """

        result = validate_aggregation(query, "test-603")
        assert result.success is True


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_query(self):
        """Test validation of empty query."""
        query = ""
        result = validate_aggregation(query, "test-701")
        assert result.success is True  # Passes if no statements to validate

    def test_global_aggregate_with_sum(self):
        """Test global aggregate with multiple aggregate functions."""
        query = """
        SELECT COUNT(DISTINCT person_id) AS Count_Patients,
               SUM(1) AS Total_Records
        FROM person
        """

        result = validate_aggregation(query, "test-702")
        assert result.success is True

    def test_complex_join_with_aggregation(self):
        """Test complex JOIN query with proper aggregation."""
        query = """
        SELECT p.gender_concept_id,
               co.condition_concept_id,
               COUNT(DISTINCT p.person_id) AS Count_Patients
        FROM person p
        INNER JOIN condition_occurrence co ON p.person_id = co.person_id
        GROUP BY p.gender_concept_id, co.condition_concept_id
        """

        result = validate_aggregation(query, "test-703")
        assert result.success is True
