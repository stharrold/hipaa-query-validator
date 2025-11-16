"""Layer 2: PHI Column Validation.

This module implements HIPAA Safe Harbor de-identification per 45 CFR § 164.514(b)(2)
by blocking all 18 HIPAA identifiers in SQL queries.

Blocked Identifiers (18 categories):
1. Names
2. Geographic subdivisions smaller than state
3. Dates (except year)
4. Telephone numbers
5. Fax numbers
6. Email addresses
7. Social Security numbers
8. Medical record numbers
9. Health plan beneficiary numbers
10. Account numbers
11. Certificate/license numbers
12. Vehicle identifiers and serial numbers
13. Device identifiers and serial numbers
14. Web URLs
15. IP addresses
16. Biometric identifiers
17. Full-face photographs
18. Any other unique identifying numbers/codes
"""

import re
from pathlib import Path
from typing import Dict, Optional, Set

import sqlparse
import yaml
from sqlparse.sql import Identifier, IdentifierList
from sqlparse.tokens import Keyword, Wildcard

from ..errors import (
    DatePHIError,
    DirectPHIIdentifierError,
    GeographicPHIError,
    SelectStarError,
)
from ..models import ValidationResult

# Compiled regex pattern for SELECT * detection
SELECT_STAR_PATTERN = re.compile(r"\bSELECT\s+\*\s+FROM\b")


class PHIValidator:
    """Validator for HIPAA PHI identifiers in SQL queries."""

    def __init__(self, phi_config_path: Optional[Path] = None) -> None:
        """Initialize PHI validator with configuration.

        Args:
            phi_config_path: Path to PHI identifiers configuration YAML file
        """
        self.phi_config = self._load_phi_config(phi_config_path)
        self.direct_identifiers = self._build_identifier_patterns("direct_identifiers")
        self.geographic_prohibited = self._build_identifier_patterns("geographic_prohibited")
        self.date_prohibited = self._build_identifier_patterns("date_prohibited")

    def _load_phi_config(self, config_path: Optional[Path]) -> Dict:
        """Load PHI identifiers from YAML configuration.

        Args:
            config_path: Path to configuration file

        Returns:
            Dictionary of PHI identifier categories
        """
        if config_path is None:
            # Use default configuration path
            config_path = (
                Path(__file__).parent.parent.parent / "config" / "schemas" / "phi_identifiers.yaml"
            )

        if not config_path.exists():
            # Return hardcoded defaults if config not found
            return self._get_default_phi_config()

        with open(config_path) as f:
            return yaml.safe_load(f)

    def _get_default_phi_config(self) -> Dict:
        """Get default PHI identifier patterns (hardcoded fallback).

        Returns:
            Dictionary of PHI identifier categories
        """
        return {
            "direct_identifiers": [
                # Names (Category 1)
                "patient_name",
                "first_name",
                "last_name",
                "middle_name",
                "given_name",
                "family_name",
                "full_name",
                "name",
                # SSN (Category 7)
                "ssn",
                "social_security_number",
                "social_security_no",
                # MRN and IDs (Categories 8-11, 18)
                "mrn",
                "medical_record_number",
                "medical_record_no",
                "patient_id",
                "health_plan_id",
                "beneficiary_id",
                "subscriber_id",
                "member_id",
                "account_number",
                "account_no",
                "certificate_number",
                "license_number",
                "driver_license",
                # Contact info (Categories 4-6)
                "phone",
                "telephone",
                "phone_number",
                "tel_no",
                "fax",
                "fax_number",
                "email",
                "email_address",
                # Device/Vehicle IDs (Categories 12-13)
                "vehicle_id",
                "vin",
                "license_plate",
                "device_id",
                "serial_number",
                "device_serial",
                # Network identifiers (Categories 14-15)
                "url",
                "web_url",
                "website",
                "ip_address",
                "ip_addr",
                "mac_address",
                # Biometric (Category 16)
                "fingerprint",
                "retinal_scan",
                "biometric",
                "facial_image",
                "photograph",
            ],
            "geographic_prohibited": [
                "street_address",
                "address",
                "address_line_1",
                "address_line_2",
                "street",
                "city",
                "town",
                "county",
                "zip",
                "zip_code",
                "zipcode",
                "postal_code",
                "latitude",
                "longitude",
                "lat",
                "lon",
                "geocode",
            ],
            "date_prohibited": [
                "birth_date",
                "birthdate",
                "date_of_birth",
                "dob",
                "death_date",
                "admission_date",
                "discharge_date",
                "visit_date",
                "month_of_birth",
                "day_of_birth",
                "month",
                "day",
            ],
        }

    def _build_identifier_patterns(self, category: str) -> Set[str]:
        """Build set of identifier patterns for a category.

        Args:
            category: PHI category name

        Returns:
            Set of lowercase column name patterns
        """
        patterns = self.phi_config.get(category, [])
        # Convert to lowercase for case-insensitive matching
        return {p.lower() for p in patterns}

    def validate_phi(self, query: str, request_id: str) -> ValidationResult:
        """Validate query does not contain PHI columns.

        Args:
            query: SQL query to validate
            request_id: Unique identifier for this validation request

        Returns:
            ValidationResult indicating success or failure

        Raises:
            SelectStarError: If SELECT * is used
            DirectPHIIdentifierError: If direct PHI identifier found
            GeographicPHIError: If prohibited geographic column found
            DatePHIError: If prohibited date column found
        """
        # Parse the SQL query
        parsed = sqlparse.parse(query)
        if not parsed:
            # Empty or invalid query - let other validators handle this
            return ValidationResult(
                success=True,
                request_id=request_id,
                layer="phi",
                message="PHI validation passed (no tokens to validate)",
            )

        # Check each statement
        for statement in parsed:
            self._validate_statement(statement)

        return ValidationResult(
            success=True,
            request_id=request_id,
            layer="phi",
            code=None,
            message="PHI validation passed - no prohibited identifiers detected",
            educational_guidance=None,
            correct_pattern=None,
        )

    def _validate_statement(self, statement: sqlparse.sql.Statement) -> None:
        """Validate a single SQL statement for PHI.

        Args:
            statement: Parsed SQL statement

        Raises:
            SelectStarError: If SELECT * found
            DirectPHIIdentifierError: If PHI identifier found
            GeographicPHIError: If geographic PHI found
            DatePHIError: If date PHI found
        """
        # Check for SELECT * in the statement string (more reliable)
        statement_upper = str(statement).upper().replace("\n", " ").replace("\t", " ")
        # Match SELECT * with optional whitespace
        if SELECT_STAR_PATTERN.search(statement_upper):
            raise SelectStarError()

        # Track which clause we're in - start with SELECT as default for first identifiers
        current_clause = "SELECT"

        for token in statement.tokens:
            # Skip whitespace and punctuation
            if token.is_whitespace or token.ttype is sqlparse.tokens.Punctuation:
                continue

            # Track SQL clauses
            if token.ttype is Keyword:
                keyword = token.value.upper()
                if keyword == "SELECT":
                    current_clause = "SELECT"
                elif keyword == "FROM":
                    current_clause = "FROM"
                elif keyword == "WHERE":
                    current_clause = "WHERE"
                elif keyword == "GROUP":
                    current_clause = "GROUP BY"
                elif keyword == "ORDER":
                    current_clause = "ORDER BY"
                elif keyword in ("JOIN", "INNER", "LEFT", "RIGHT", "OUTER"):
                    current_clause = "JOIN"
                elif keyword == "ON":
                    current_clause = "ON"

            # Check for SELECT * (token-based)
            if token.ttype is Wildcard:
                raise SelectStarError()

            # Also check if token value is "*" and not whitespace
            if str(token).strip() == "*" and not token.is_whitespace:
                raise SelectStarError()

            # Check for WHERE/HAVING clauses (sqlparse packages these as objects)
            if isinstance(token, sqlparse.sql.Where):
                self._check_tokens_for_identifiers(token.tokens, "WHERE")
            # Check identifiers (column names)
            elif isinstance(token, Identifier):
                self._check_identifier(token, current_clause)
            elif isinstance(token, IdentifierList):
                for identifier in token.get_identifiers():
                    self._check_identifier(identifier, current_clause)
            # Also recursively check other complex tokens in WHERE/ON/HAVING context
            elif hasattr(token, "tokens") and current_clause in ("WHERE", "ON", "HAVING"):
                # Recursively check sub-tokens in WHERE/ON/HAVING clauses
                self._check_tokens_for_identifiers(token.tokens, current_clause)

    def _check_tokens_for_identifiers(self, tokens: list, clause: str) -> None:
        """Recursively check tokens for identifiers (for WHERE/ON/HAVING clauses).

        Args:
            tokens: List of tokens to check
            clause: SQL clause context
        """
        for token in tokens:
            if isinstance(token, Identifier):
                self._check_identifier(token, clause)
            elif isinstance(token, IdentifierList):
                for identifier in token.get_identifiers():
                    if isinstance(identifier, Identifier):
                        self._check_identifier(identifier, clause)
                    else:
                        # Check non-Identifier items too
                        self._check_token_for_phi(identifier, clause)
            else:
                # Check other token types
                self._check_token_for_phi(token, clause)

            # Recurse into nested tokens
            if hasattr(token, "tokens"):
                self._check_tokens_for_identifiers(token.tokens, clause)

    def _check_token_for_phi(self, token: object, clause: str) -> None:
        """Check any token for PHI patterns.

        Checks non-Identifier tokens for PHI column names.
        Complements _check_identifier for comprehensive coverage.

        Args:
            token: Token to check for PHI patterns
            clause: SQL clause context
        """
        # Skip if no value or is whitespace/punctuation
        if not hasattr(token, "value"):
            return

        value = token.value
        if not value or token.is_whitespace:
            return

        # Skip keywords and wildcards
        if hasattr(token, "ttype") and token.ttype in (Keyword, Wildcard):
            return

        # Skip punctuation
        if hasattr(token, "ttype") and token.ttype is sqlparse.tokens.Punctuation:
            return

        # Check value against PHI patterns
        column_lower = str(value).lower()

        if column_lower in self.direct_identifiers:
            raise DirectPHIIdentifierError(
                column_name=str(value),
                identifier_type=self._get_identifier_type(column_lower),
                clause=clause,
            )

        if column_lower in self.geographic_prohibited:
            raise GeographicPHIError(column_name=str(value), clause=clause)

        if column_lower in self.date_prohibited:
            raise DatePHIError(column_name=str(value), clause=clause)

    def _check_identifier(self, identifier: Identifier, clause: str) -> None:
        """Check if an identifier is a PHI column.

        Args:
            identifier: SQL identifier to check
            clause: SQL clause where identifier was found

        Raises:
            DirectPHIIdentifierError: If direct PHI identifier
            GeographicPHIError: If geographic PHI
            DatePHIError: If date PHI
        """
        # Get the actual column name (handle aliases, table prefixes)
        column_name = self._extract_column_name(identifier)
        if not column_name:
            return

        column_lower = column_name.lower()

        # Check against PHI categories
        if column_lower in self.direct_identifiers:
            raise DirectPHIIdentifierError(
                column_name=column_name,
                identifier_type=self._get_identifier_type(column_lower),
                clause=clause,
            )

        if column_lower in self.geographic_prohibited:
            raise GeographicPHIError(column_name=column_name, clause=clause)

        if column_lower in self.date_prohibited:
            raise DatePHIError(column_name=column_name, clause=clause)

    def _extract_column_name(self, identifier: Identifier) -> Optional[str]:
        """Extract the actual column name from an identifier.

        Handles:
        - Simple column names: person_id
        - Table-qualified names: person.person_id
        - Aliased columns: gender_concept_id AS gender
        - Function calls: COUNT(DISTINCT person_id)

        Args:
            identifier: SQL identifier

        Returns:
            Column name or None if not extractable
        """
        # Get the real name (before alias)
        name = identifier.get_real_name()
        if name:
            return name

        # Try to get the full name
        name = identifier.get_name()
        if name:
            # Remove table prefix if present (e.g., "person.person_id" -> "person_id")
            if "." in name:
                name = name.split(".")[-1]
            return name

        return None

    def _get_identifier_type(self, column_name: str) -> str:
        """Get the type of PHI identifier.

        Args:
            column_name: Column name (lowercase)

        Returns:
            Human-readable identifier type
        """
        # Map common patterns to identifier types
        if any(pattern in column_name for pattern in ["name", "first", "last", "given", "family"]):
            return "name (Category 1)"
        if any(pattern in column_name for pattern in ["ssn", "social_security"]):
            return "SSN (Category 7)"
        if any(pattern in column_name for pattern in ["mrn", "medical_record"]):
            return "medical record number (Category 8)"
        if any(pattern in column_name for pattern in ["phone", "telephone", "tel", "fax"]):
            return "telephone/fax number (Categories 4-5)"
        if "email" in column_name:
            return "email address (Category 6)"
        if any(
            pattern in column_name for pattern in ["account", "beneficiary", "subscriber", "member"]
        ):
            return "account/beneficiary number (Categories 9-10)"
        if any(pattern in column_name for pattern in ["license", "certificate", "driver"]):
            return "license/certificate number (Category 11)"
        if any(pattern in column_name for pattern in ["vehicle", "vin", "license_plate"]):
            return "vehicle identifier (Category 12)"
        if any(pattern in column_name for pattern in ["device", "serial"]):
            return "device identifier (Category 13)"
        if any(pattern in column_name for pattern in ["url", "web", "ip", "mac"]):
            return "web/IP identifier (Categories 14-15)"
        if any(
            pattern in column_name for pattern in ["fingerprint", "biometric", "retinal", "facial"]
        ):
            return "biometric identifier (Category 16)"

        return "unique identifier (Category 18)"


def validate_phi(
    query: str, request_id: str, config_path: Optional[Path] = None
) -> ValidationResult:
    """Validate query for PHI columns (convenience function).

    Args:
        query: SQL query to validate
        request_id: Unique identifier for this validation request
        config_path: Optional path to PHI configuration file

    Returns:
        ValidationResult indicating success or failure
    """
    validator = PHIValidator(config_path)
    return validator.validate_phi(query, request_id)
