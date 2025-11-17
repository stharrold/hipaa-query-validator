"""Unit tests for Layer 1: Schema validation."""

import pytest

from src.errors import UnknownColumnError, UnknownTableError
from src.validators.schema import validate_schema


class TestValidTables:
    """Test valid table references."""

    def test_valid_person_table(self):
        """Valid query with person table."""
        query = "SELECT person_id FROM person"
        result = validate_schema(query, "test-001")
        assert result.success is True
        assert result.layer == "schema"

    def test_valid_condition_occurrence_table(self):
        """Valid query with condition_occurrence table."""
        query = "SELECT condition_occurrence_id FROM condition_occurrence"
        result = validate_schema(query, "test-002")
        assert result.success is True

    def test_case_insensitive_table(self):
        """Table names are case-insensitive."""
        query = "SELECT person_id FROM PERSON"
        result = validate_schema(query, "test-003")
        assert result.success is True

    def test_multiple_tables_join(self):
        """Valid query with JOIN."""
        query = """
        SELECT p.person_id, c.condition_concept_id
        FROM person p
        JOIN condition_occurrence c ON p.person_id = c.person_id
        """
        result = validate_schema(query, "test-004")
        assert result.success is True

    def test_schema_qualified_table(self):
        """Table with schema prefix (dbo.person)."""
        query = "SELECT person_id FROM dbo.person"
        result = validate_schema(query, "test-005")
        assert result.success is True


class TestInvalidTables:
    """Test invalid table references."""

    def test_invalid_table_name(self):
        """Invalid table should raise UnknownTableError."""
        query = "SELECT * FROM invalid_table"

        with pytest.raises(UnknownTableError) as exc_info:
            validate_schema(query, "test-101")

        error = exc_info.value
        assert error.code == "E101"
        assert error.layer == "schema"
        assert "invalid_table" in str(error).lower()
        assert "not found" in str(error).lower()

    def test_typo_in_table_name(self):
        """Typo in table name should raise error."""
        query = "SELECT * FROM persn"  # typo: persn instead of person

        with pytest.raises(UnknownTableError) as exc_info:
            validate_schema(query, "test-102")

        assert exc_info.value.code == "E101"
        assert "persn" in str(exc_info.value)

    def test_invalid_table_shows_valid_tables(self):
        """Error message should show valid tables."""
        query = "SELECT * FROM bad_table"

        with pytest.raises(UnknownTableError) as exc_info:
            validate_schema(query, "test-103")

        error_msg = str(exc_info.value)
        # Should include sample of valid tables
        assert "person" in error_msg.lower()


class TestValidColumns:
    """Test valid column references."""

    def test_valid_person_columns(self):
        """Valid columns in person table."""
        query = "SELECT person_id, gender_concept_id, year_of_birth FROM person"
        result = validate_schema(query, "test-201")
        assert result.success is True

    def test_qualified_column_reference(self):
        """Qualified column reference (table.column)."""
        query = "SELECT person.person_id FROM person"
        result = validate_schema(query, "test-202")
        assert result.success is True

    def test_aliased_table_column_reference(self):
        """Column reference with table alias."""
        query = "SELECT p.person_id FROM person p"
        result = validate_schema(query, "test-203")
        assert result.success is True

    def test_column_in_where_clause(self):
        """Valid column in WHERE clause."""
        query = "SELECT person_id FROM person WHERE year_of_birth > 1980"
        result = validate_schema(query, "test-204")
        assert result.success is True

    def test_column_in_join_on_clause(self):
        """Valid column in JOIN ON clause."""
        query = """
        SELECT p.person_id
        FROM person p
        JOIN condition_occurrence c ON p.person_id = c.person_id
        """
        result = validate_schema(query, "test-205")
        assert result.success is True

    def test_case_insensitive_column(self):
        """Column names are case-insensitive."""
        query = "SELECT PERSON_ID, Person_Id, person_id FROM person"
        result = validate_schema(query, "test-206")
        assert result.success is True

    def test_case_insensitive_qualified_column(self):
        """Qualified columns with uppercase table names should validate."""
        query = "SELECT PERSON.person_id FROM PERSON"
        result = validate_schema(query, "test-case-qual")
        assert result.success is True

    def test_case_insensitive_alias_column(self):
        """Qualified columns with uppercase aliases should validate."""
        query = "SELECT P.person_id FROM person P"
        result = validate_schema(query, "test-case-alias")
        assert result.success is True

    def test_valid_unqualified_column(self):
        """Valid unqualified column should pass."""
        query = "SELECT person_id FROM person"
        result = validate_schema(query, "test-unqual-valid")
        assert result.success is True

    def test_ambiguous_unqualified_column_allowed(self):
        """Ambiguous unqualified column (exists in multiple tables) should pass."""
        query = """
        SELECT person_id
        FROM person p
        JOIN condition_occurrence c ON p.person_id = c.person_id
        """
        # Both tables have person_id - validator allows, DB will require qualification
        result = validate_schema(query, "test-unqual-ambig")
        assert result.success is True


class TestInvalidColumns:
    """Test invalid column references."""

    def test_invalid_column_in_person(self):
        """Invalid column should raise UnknownColumnError."""
        query = "SELECT person.invalid_column FROM person"

        with pytest.raises(UnknownColumnError) as exc_info:
            validate_schema(query, "test-301")

        error = exc_info.value
        assert error.code == "E102"
        assert error.layer == "schema"
        assert "invalid_column" in str(error)
        assert "person" in str(error)

    def test_column_from_wrong_table(self):
        """Column that exists in different table."""
        query = "SELECT person.condition_occurrence_id FROM person"

        with pytest.raises(UnknownColumnError) as exc_info:
            validate_schema(query, "test-302")

        assert exc_info.value.code == "E102"
        assert "condition_occurrence_id" in str(exc_info.value)

    def test_invalid_column_with_alias(self):
        """Invalid column with table alias."""
        query = "SELECT p.bad_column FROM person p"

        with pytest.raises(UnknownColumnError) as exc_info:
            validate_schema(query, "test-303")

        assert exc_info.value.code == "E102"
        assert "bad_column" in str(exc_info.value)

    def test_invalid_unqualified_column(self):
        """Invalid unqualified column should raise error."""
        query = "SELECT bad_column FROM person"
        with pytest.raises(UnknownColumnError) as exc_info:
            validate_schema(query, "test-unqual-invalid")
        assert "bad_column" in str(exc_info.value)

    def test_invalid_column_shows_valid_columns(self):
        """Error message should show valid columns."""
        query = "SELECT person.fake_col FROM person"

        with pytest.raises(UnknownColumnError) as exc_info:
            validate_schema(query, "test-304")

        error_msg = str(exc_info.value)
        # Should include sample of valid columns
        assert "person_id" in error_msg


class TestEdgeCases:
    """Test edge cases and complex queries."""

    def test_function_with_column(self):
        """COUNT(column_name) should validate column."""
        query = "SELECT COUNT(person_id) FROM person"
        result = validate_schema(query, "test-401")
        assert result.success is True

    def test_function_with_distinct(self):
        """COUNT(DISTINCT column) should validate."""
        query = "SELECT COUNT(DISTINCT person_id) FROM person"
        result = validate_schema(query, "test-402")
        assert result.success is True

    def test_multiple_tables_multiple_columns(self):
        """Complex query with multiple tables and columns."""
        query = """
        SELECT
            p.person_id,
            p.gender_concept_id,
            c.condition_concept_id,
            c.condition_type_concept_id
        FROM person p
        JOIN condition_occurrence c ON p.person_id = c.person_id
        WHERE p.year_of_birth > 1980
        GROUP BY p.gender_concept_id, c.condition_concept_id
        """
        result = validate_schema(query, "test-403")
        assert result.success is True

    def test_column_with_alias(self):
        """Column with AS alias."""
        query = "SELECT person_id AS patient_id FROM person"
        result = validate_schema(query, "test-404")
        assert result.success is True

    def test_aggregate_functions(self):
        """Various aggregate functions."""
        query = """
        SELECT
            COUNT(DISTINCT person_id) AS Count_Patients,
            AVG(year_of_birth) AS Avg_Year,
            MIN(year_of_birth) AS Min_Year
        FROM person
        """
        result = validate_schema(query, "test-405")
        assert result.success is True

    def test_empty_query_handled(self):
        """Empty query should not crash."""
        query = "   \n\t  "
        # Schema validator should return success for empty query
        # (ASCII validator will catch it first)
        result = validate_schema(query, "test-406")
        assert result.success is True


class TestComplexQueries:
    """Test complex real-world queries."""

    def test_complex_analytics_query(self):
        """Complex analytics query from real use case."""
        query = """
        SELECT
            p.gender_concept_id,
            p.race_concept_id,
            COUNT(DISTINCT p.person_id) AS Count_Patients,
            COUNT(DISTINCT c.condition_occurrence_id) AS Count_Conditions
        FROM person p
        JOIN condition_occurrence c ON p.person_id = c.person_id
        WHERE p.year_of_birth BETWEEN 1950 AND 2000
        GROUP BY p.gender_concept_id, p.race_concept_id
        """
        result = validate_schema(query, "test-501")
        assert result.success is True

    def test_three_table_join(self):
        """Query with three table join."""
        query = """
        SELECT
            p.person_id,
            c.condition_concept_id,
            v.visit_concept_id
        FROM person p
        JOIN condition_occurrence c ON p.person_id = c.person_id
        JOIN visit_occurrence v ON c.visit_occurrence_id = v.visit_occurrence_id
        """
        result = validate_schema(query, "test-502")
        assert result.success is True

    def test_measurement_query(self):
        """Query on measurement table."""
        query = """
        SELECT
            m.measurement_concept_id,
            COUNT(DISTINCT m.person_id) AS Count_Patients,
            AVG(m.value_as_number) AS Avg_Value
        FROM measurement m
        GROUP BY m.measurement_concept_id
        """
        result = validate_schema(query, "test-503")
        assert result.success is True


class TestPerformance:
    """Performance tests."""

    def test_schema_validation_performance(self):
        """Schema validation should be fast."""
        import time

        query = """
        SELECT p.person_id, p.gender_concept_id
        FROM person p
        WHERE p.year_of_birth > 1980
        """

        # Run 1000 validations
        start = time.perf_counter()
        for i in range(1000):
            validate_schema(query, f"perf-{i}")
        duration = time.perf_counter() - start

        # Should complete in < 3 seconds total (3ms per query)
        # This is acceptable given the complexity of sqlparse traversal
        assert (
            duration < 3.0
        ), f"Performance regression: {duration:.2f}s for 1000 queries ({duration:.1f}ms per query)"
