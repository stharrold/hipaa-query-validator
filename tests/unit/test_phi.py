"""Unit tests for Layer 2: PHI Column Validation.

Tests validate that queries do not contain the 18 HIPAA identifiers
per 45 CFR § 164.514(b)(2).
"""

import pytest

from src.errors import (
    DatePHIError,
    DirectPHIIdentifierError,
    GeographicPHIError,
    SelectStarError,
)
from src.validators.phi import validate_phi


class TestValidNonPHIQueries:
    """Tests for valid queries with no PHI that should pass validation."""

    def test_simple_aggregate_query(self):
        """Test simple aggregate query with allowed columns."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """
        result = validate_phi(query, "test-001")
        assert result.success is True
        assert result.layer == "phi"

    def test_multiple_dimensions(self):
        """Test query with multiple non-PHI dimensions."""
        query = """
        SELECT gender_concept_id,
               race_concept_id,
               year_of_birth,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id, race_concept_id, year_of_birth
        """
        result = validate_phi(query, "test-002")
        assert result.success is True

    def test_condition_occurrence_query(self):
        """Test query on condition_occurrence table."""
        query = """
        SELECT condition_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM condition_occurrence
        GROUP BY condition_concept_id
        """
        result = validate_phi(query, "test-003")
        assert result.success is True

    def test_join_query_no_phi(self):
        """Test JOIN query with no PHI columns."""
        query = """
        SELECT p.gender_concept_id,
               COUNT(DISTINCT p.person_id) AS Count_Patients
        FROM person p
        JOIN condition_occurrence co ON p.person_id = co.person_id
        GROUP BY p.gender_concept_id
        """
        result = validate_phi(query, "test-004")
        assert result.success is True

    def test_state_level_geography(self):
        """Test query with state-level geography (allowed)."""
        query = """
        SELECT state,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person p
        JOIN location l ON p.location_id = l.location_id
        GROUP BY state
        """
        result = validate_phi(query, "test-005")
        assert result.success is True


class TestSelectStarRejection:
    """Tests for SELECT * rejection."""

    def test_simple_select_star(self):
        """Test rejection of simple SELECT *."""
        query = "SELECT * FROM person"

        with pytest.raises(SelectStarError) as exc_info:
            validate_phi(query, "test-101")

        error = exc_info.value
        assert error.code == "E204"
        assert error.layer == "phi"

    def test_select_star_with_where(self):
        """Test rejection of SELECT * with WHERE clause."""
        query = "SELECT * FROM person WHERE gender_concept_id = 8507"

        with pytest.raises(SelectStarError):
            validate_phi(query, "test-102")

    def test_select_star_with_group_by(self):
        """Test rejection of SELECT * with GROUP BY."""
        query = "SELECT * FROM person GROUP BY gender_concept_id"

        with pytest.raises(SelectStarError):
            validate_phi(query, "test-103")


class TestDirectPHIIdentifiers:
    """Tests for direct PHI identifier rejection (Category 1-18)."""

    def test_patient_name(self):
        """Test rejection of patient_name (Category 1: Names)."""
        query = "SELECT patient_name FROM person"

        with pytest.raises(DirectPHIIdentifierError) as exc_info:
            validate_phi(query, "test-201")

        error = exc_info.value
        assert error.code == "E201"
        assert "patient_name" in error.details["column_name"].lower()
        assert error.details["clause"] == "SELECT"

    def test_first_name(self):
        """Test rejection of first_name."""
        query = "SELECT first_name, last_name FROM person"

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-202")

    def test_ssn(self):
        """Test rejection of SSN (Category 7)."""
        query = "SELECT ssn FROM person WHERE gender_concept_id = 8507"

        with pytest.raises(DirectPHIIdentifierError) as exc_info:
            validate_phi(query, "test-203")

        error = exc_info.value
        assert "ssn" in error.details["column_name"].lower()

    def test_mrn(self):
        """Test rejection of MRN (Category 8)."""
        query = "SELECT mrn, gender_concept_id FROM person"

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-204")

    def test_email_address(self):
        """Test rejection of email (Category 6)."""
        query = """
        SELECT email_address,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY email_address
        """

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-205")

    def test_phone_number(self):
        """Test rejection of phone number (Category 4)."""
        query = "SELECT phone_number FROM person"

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-206")

    def test_ip_address(self):
        """Test rejection of IP address (Category 15)."""
        query = "SELECT ip_address FROM audit_log"

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-207")

    def test_phi_in_where_clause(self):
        """Test rejection of PHI in WHERE clause."""
        query = "SELECT gender_concept_id FROM person WHERE patient_name = 'Smith'"

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-208")

        # WHERE clause may be detected as part of token parsing

    def test_phi_in_group_by(self):
        """Test rejection of PHI in GROUP BY clause."""
        query = """
        SELECT ssn,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY ssn
        """

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-209")


class TestGeographicPHI:
    """Tests for geographic PHI rejection (Category 2)."""

    def test_city(self):
        """Test rejection of city."""
        query = """
        SELECT city,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person p
        JOIN location l ON p.location_id = l.location_id
        GROUP BY city
        """

        with pytest.raises(GeographicPHIError) as exc_info:
            validate_phi(query, "test-301")

        error = exc_info.value
        assert error.code == "E202"
        assert "city" in error.details["column_name"].lower()

    def test_zip_code(self):
        """Test rejection of ZIP code."""
        query = "SELECT zip_code FROM location"

        with pytest.raises(GeographicPHIError):
            validate_phi(query, "test-302")

    def test_street_address(self):
        """Test rejection of street address."""
        query = "SELECT street_address FROM location"

        with pytest.raises(GeographicPHIError):
            validate_phi(query, "test-303")

    def test_county(self):
        """Test rejection of county."""
        query = """
        SELECT county,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person p
        JOIN location l ON p.location_id = l.location_id
        GROUP BY county
        """

        with pytest.raises(GeographicPHIError):
            validate_phi(query, "test-304")

    def test_latitude_longitude(self):
        """Test rejection of coordinates."""
        query = "SELECT latitude, longitude FROM location"

        with pytest.raises(GeographicPHIError):
            validate_phi(query, "test-305")


class TestDatePHI:
    """Tests for date PHI rejection (Category 3)."""

    def test_birth_date(self):
        """Test rejection of birth_date."""
        query = "SELECT birth_date FROM person"

        with pytest.raises(DatePHIError) as exc_info:
            validate_phi(query, "test-401")

        error = exc_info.value
        assert error.code == "E203"
        assert "birth_date" in error.details["column_name"].lower()

    def test_month_of_birth(self):
        """Test rejection of month_of_birth."""
        query = """
        SELECT month_of_birth,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY month_of_birth
        """

        with pytest.raises(DatePHIError):
            validate_phi(query, "test-402")

    def test_admission_date(self):
        """Test rejection of admission_date."""
        query = """
        SELECT admission_date,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM visit_occurrence
        GROUP BY admission_date
        """

        with pytest.raises(DatePHIError):
            validate_phi(query, "test-403")

    def test_year_allowed(self):
        """Test that year_of_birth is allowed (year only, not full date)."""
        query = """
        SELECT year_of_birth,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY year_of_birth
        """

        result = validate_phi(query, "test-404")
        assert result.success is True


class TestCaseInsensitivity:
    """Tests for case-insensitive PHI detection."""

    def test_uppercase_phi(self):
        """Test detection of PHI in uppercase."""
        query = "SELECT PATIENT_NAME FROM PERSON"

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-501")

    def test_mixed_case_phi(self):
        """Test detection of PHI in mixed case."""
        query = "SELECT Patient_Name FROM person"

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-502")

    def test_lowercase_phi(self):
        """Test detection of PHI in lowercase."""
        query = "SELECT patient_name FROM person"

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-503")


class TestTableQualifiedColumns:
    """Tests for PHI detection in table-qualified column names."""

    def test_qualified_phi_column(self):
        """Test detection of PHI in table-qualified column (table.column)."""
        query = "SELECT p.patient_name FROM person p"

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-601")

    def test_qualified_valid_column(self):
        """Test valid table-qualified non-PHI column."""
        query = """
        SELECT p.gender_concept_id,
               COUNT(DISTINCT p.person_id) AS Count_Patients
        FROM person p
        GROUP BY p.gender_concept_id
        """

        result = validate_phi(query, "test-602")
        assert result.success is True


class TestAliasedColumns:
    """Tests for PHI detection with column aliases."""

    def test_phi_column_with_alias(self):
        """Test that aliasing PHI column doesn't bypass detection."""
        query = "SELECT patient_name AS name FROM person"

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-701")

    def test_valid_column_with_alias(self):
        """Test valid column with alias."""
        query = """
        SELECT gender_concept_id AS gender,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """

        result = validate_phi(query, "test-702")
        assert result.success is True


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_query(self):
        """Test validation of empty query (should pass PHI validation)."""
        query = ""
        result = validate_phi(query, "test-801")
        assert result.success is True  # PHI validator passes empty queries

    def test_query_with_comments(self):
        """Test query with SQL comments."""
        query = """
        -- This query gets gender distribution
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """

        result = validate_phi(query, "test-802")
        assert result.success is True

    def test_multiple_phi_violations(self):
        """Test query with multiple PHI violations (first one should be caught)."""
        query = "SELECT patient_name, ssn, birth_date FROM person"

        with pytest.raises(DirectPHIIdentifierError):
            # Should catch first PHI column encountered
            validate_phi(query, "test-803")


class TestEnhancedPHIDetection:
    """Tests for enhanced PHI detection across all token types (Issue #9)."""

    def test_phi_detection_in_non_identifier_tokens(self):
        """Test PHI detection works for bare column name tokens."""
        # Test case where PHI might appear as bare token
        query = "SELECT ssn FROM person"  # ssn as bare name

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-phi-token-1")

    def test_phi_in_comparison_values(self):
        """Test that PHI column names like 'email' are detected in WHERE clause conditions."""
        query = "SELECT id FROM person WHERE email = 'test@example.com'"

        with pytest.raises(DirectPHIIdentifierError):
            validate_phi(query, "test-phi-token-2")

    def test_string_literals_not_flagged_as_phi(self):
        """Test that string literal values containing PHI patterns are not flagged."""
        # The column name 'description' is allowed, the value 'email' is a string literal
        query = "SELECT person_id FROM person WHERE description = 'email'"
        result = validate_phi(query, "test-phi-string-literal-001")
        assert result.success is True  # String literal 'email' should not be flagged

        # Another test: PHI pattern in string value
        query = "SELECT person_id FROM person WHERE note = 'patient_name is important'"
        result = validate_phi(query, "test-phi-string-literal-002")
        assert result.success is True  # 'patient_name' as string value should pass
