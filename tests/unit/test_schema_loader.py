"""Unit tests for schema loading and caching."""

import pytest

from src.schemas.loader import SchemaCache, schema_cache


class TestSchemaLoading:
    """Test schema loading from YAML configuration."""

    def test_schema_loaded(self):
        """Verify schema loaded successfully with expected tables."""
        tables = schema_cache.get_valid_tables()
        assert len(tables) > 0, "Schema should have tables"
        assert "person" in tables
        assert "condition_occurrence" in tables
        assert "drug_exposure" in tables
        assert "measurement" in tables
        assert "observation" in tables

    def test_singleton_pattern(self):
        """Verify SchemaCache uses singleton pattern."""
        cache1 = SchemaCache()
        cache2 = SchemaCache()
        assert cache1 is cache2, "Should return same instance"
        assert cache1 is schema_cache, "Should match global instance"


class TestValidTableCheck:
    """Test valid table detection."""

    def test_valid_person_table(self):
        """Person table should be valid."""
        assert schema_cache.is_valid_table("person")

    def test_valid_condition_occurrence_table(self):
        """Condition_occurrence table should be valid."""
        assert schema_cache.is_valid_table("condition_occurrence")

    def test_case_insensitive_table(self):
        """Table names should be case-insensitive."""
        assert schema_cache.is_valid_table("person")
        assert schema_cache.is_valid_table("PERSON")
        assert schema_cache.is_valid_table("Person")
        assert schema_cache.is_valid_table("PeRsOn")

    def test_invalid_table(self):
        """Invalid table should return False."""
        assert not schema_cache.is_valid_table("invalid_table")
        assert not schema_cache.is_valid_table("not_a_table")
        assert not schema_cache.is_valid_table("fake_table_name")


class TestValidColumnCheck:
    """Test valid column detection."""

    def test_valid_person_columns(self):
        """Person table columns should be valid."""
        assert schema_cache.is_valid_column("person", "person_id")
        assert schema_cache.is_valid_column("person", "gender_concept_id")
        assert schema_cache.is_valid_column("person", "year_of_birth")
        assert schema_cache.is_valid_column("person", "race_concept_id")

    def test_case_insensitive_column(self):
        """Column names should be case-insensitive."""
        assert schema_cache.is_valid_column("person", "person_id")
        assert schema_cache.is_valid_column("person", "PERSON_ID")
        assert schema_cache.is_valid_column("person", "Person_Id")
        assert schema_cache.is_valid_column("PERSON", "person_id")
        assert schema_cache.is_valid_column("Person", "PERSON_ID")

    def test_invalid_column_in_person(self):
        """Invalid column in person should return False."""
        assert not schema_cache.is_valid_column("person", "invalid_column")
        assert not schema_cache.is_valid_column("person", "fake_col")

    def test_column_from_wrong_table(self):
        """Column that exists in different table should return False."""
        # condition_occurrence_id exists in condition_occurrence, not person
        assert not schema_cache.is_valid_column("person", "condition_occurrence_id")

    def test_invalid_table_returns_false(self):
        """Checking column in invalid table should return False."""
        assert not schema_cache.is_valid_column("invalid_table", "any_column")


class TestGetValidTables:
    """Test getting list of valid tables."""

    def test_get_all_tables(self):
        """Should return all tables from schema."""
        tables = schema_cache.get_valid_tables()
        assert isinstance(tables, set)
        assert len(tables) > 0
        # Check for key OMOP tables
        expected_tables = [
            "person",
            "observation_period",
            "visit_occurrence",
            "condition_occurrence",
            "drug_exposure",
            "procedure_occurrence",
            "measurement",
            "observation",
            "death",
            "location",
            "care_site",
            "provider",
            "concept",
        ]
        for table in expected_tables:
            assert table in tables, f"Expected table '{table}' in schema"


class TestGetValidColumns:
    """Test getting list of valid columns for a table."""

    def test_get_person_columns(self):
        """Should return all columns for person table."""
        columns = schema_cache.get_valid_columns("person")
        assert isinstance(columns, set)
        assert len(columns) > 0
        # Check for key person columns
        expected_columns = [
            "person_id",
            "gender_concept_id",
            "year_of_birth",
            "race_concept_id",
            "ethnicity_concept_id",
        ]
        for col in expected_columns:
            assert col in columns, f"Expected column '{col}' in person table"

    def test_get_columns_case_insensitive(self):
        """Should return columns regardless of table name case."""
        columns_lower = schema_cache.get_valid_columns("person")
        columns_upper = schema_cache.get_valid_columns("PERSON")
        assert columns_lower == columns_upper

    def test_get_columns_invalid_table(self):
        """Should return empty set for invalid table."""
        columns = schema_cache.get_valid_columns("invalid_table")
        assert isinstance(columns, set)
        assert len(columns) == 0


class TestPerformance:
    """Test performance of schema cache."""

    def test_cache_performance(self):
        """Schema cache should enable fast lookups."""
        import time

        # Warm up cache
        schema_cache.is_valid_table("person")

        # Test 10,000 lookups
        start = time.perf_counter()
        for _ in range(10000):
            schema_cache.is_valid_table("person")
            schema_cache.is_valid_column("person", "person_id")
        duration = time.perf_counter() - start

        # Should complete in < 0.1 seconds (10 microseconds per lookup pair)
        assert duration < 0.1, f"Performance regression: {duration:.3f}s for 10,000 lookup pairs"
