"""Layer 4: SQL Enforcement Wrapper.

This module wraps validated queries with minimum patient count enforcement:
WHERE Count_Patients >= 20000

Key security features:
- Anti-spoofing: wrapper executes AFTER user's WHERE clause
- Prevents k-anonymity violations (k >= 20,000)
- Cannot be circumvented via subqueries (blocked by Layer 4 validation)
- Cannot be circumvented via CTEs (blocked by Layer 4 validation)

The 20,000 patient threshold is based on HIPAA Safe Harbor guidance and
provides strong privacy protection for aggregate data.
"""

import re

import sqlparse
from sqlparse.tokens import Keyword

from .errors import CTENotAllowedError, SubqueryNotAllowedError
from .models import ValidationResult


# Minimum patient count threshold (per HIPAA Safe Harbor guidance)
MIN_PATIENT_COUNT = 20000

# Compiled regex pattern for subquery detection
SUBQUERY_PATTERN = re.compile(r"\(\s*SELECT\s", re.IGNORECASE)


class SQLEnforcer:
    """Enforces minimum patient count threshold via SQL wrapper."""

    def __init__(self, min_patient_count: int = MIN_PATIENT_COUNT) -> None:
        """Initialize SQL enforcer.

        Args:
            min_patient_count: Minimum patient count threshold (default: 20000)
        """
        self.min_patient_count = min_patient_count

    def validate_no_circumvention(self, query: str, request_id: str) -> ValidationResult:
        """Validate query doesn't attempt to circumvent enforcement wrapper.

        Checks for:
        - Subqueries (nested SELECT statements)
        - CTEs (WITH clauses)

        Args:
            query: SQL query to validate
            request_id: Unique identifier for this validation request

        Returns:
            ValidationResult indicating success or failure

        Raises:
            SubqueryNotAllowedError: If subquery detected
            CTENotAllowedError: If CTE detected
        """
        # Parse the query
        parsed = sqlparse.parse(query)
        if not parsed:
            return ValidationResult(
                success=True,
                request_id=request_id,
                layer="enforcement",
                message="Enforcement validation passed (no statements to validate)",
            )

        for statement in parsed:
            self._check_for_circumvention(statement)

        return ValidationResult(
            success=True,
            request_id=request_id,
            layer="enforcement",
            code=None,
            message="Enforcement validation passed - no circumvention attempts detected",
            educational_guidance=None,
            correct_pattern=None,
        )

    def _check_for_circumvention(self, statement: sqlparse.sql.Statement) -> None:
        """Check a statement for circumvention attempts.

        Args:
            statement: Parsed SQL statement

        Raises:
            SubqueryNotAllowedError: If subquery detected
            CTENotAllowedError: If CTE detected
        """
        # Check for CTEs (WITH clause)
        if self._has_cte(statement):
            raise CTENotAllowedError()

        # Check for subqueries
        if self._has_subquery(statement):
            raise SubqueryNotAllowedError()

    def _has_cte(self, statement: sqlparse.sql.Statement) -> bool:
        """Check if statement has Common Table Expression (WITH clause).

        Args:
            statement: Parsed SQL statement

        Returns:
            True if CTE found, False otherwise
        """
        for token in statement.tokens:
            if token.ttype is Keyword and token.value.upper() == "WITH":
                return True
        return False

    def _has_subquery(self, statement: sqlparse.sql.Statement) -> bool:
        """Check if statement has subqueries (nested SELECT).

        Args:
            statement: Parsed SQL statement

        Returns:
            True if subquery found, False otherwise
        """
        # Method 1: Count SELECT keywords - if more than 1, there's a subquery
        select_count = 0

        def count_selects(tokens):
            nonlocal select_count
            for token in tokens:
                if hasattr(token, "tokens"):
                    # Recursively check nested tokens
                    count_selects(token.tokens)
                elif token.ttype is Keyword and token.value.upper() == "SELECT":
                    select_count += 1

        count_selects(statement.tokens)

        if select_count > 1:
            return True

        # Method 2: Check for parenthesized subqueries using regex
        statement_str = str(statement).upper()
        # Look for SELECT inside parentheses (subquery pattern)
        if SUBQUERY_PATTERN.search(statement_str):
            return True

        return False

    def wrap_query(self, query: str) -> str:
        """Wrap validated query with minimum patient count enforcement.

        The wrapper executes as: SELECT * FROM (user_query) WHERE Count_Patients >= 20000

        This ensures:
        1. User's query executes first (including their WHERE clause)
        2. Results are aggregated per user's GROUP BY
        3. Only rows with >= 20,000 patients are returned
        4. User cannot circumvent the threshold

        Args:
            query: Validated SQL query to wrap

        Returns:
            Wrapped query with threshold enforcement

        Example:
            Input:
                SELECT gender_concept_id,
                       COUNT(DISTINCT person_id) AS Count_Patients
                FROM person
                GROUP BY gender_concept_id

            Output:
                SELECT * FROM (
                    SELECT gender_concept_id,
                           COUNT(DISTINCT person_id) AS Count_Patients
                    FROM person
                    GROUP BY gender_concept_id
                ) AS validated_query
                WHERE Count_Patients >= 20000
        """
        # Remove trailing semicolon if present
        query = query.rstrip().rstrip(";")

        # Wrap the query
        wrapped = f"""SELECT * FROM (
    {query}
) AS validated_query
WHERE Count_Patients >= {self.min_patient_count}"""

        return wrapped

    def unwrap_query(self, wrapped_query: str) -> str:
        """Extract original query from wrapped query.

        Useful for logging and debugging.

        Args:
            wrapped_query: Wrapped query with enforcement

        Returns:
            Original unwrapped query
        """
        # Pattern to match wrapped query
        pattern = r"SELECT \* FROM \(\s*(.+?)\s*\) AS validated_query\s+WHERE Count_Patients >= \d+"

        match = re.search(pattern, wrapped_query, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()

        # If not wrapped, return as-is
        return wrapped_query


def validate_no_circumvention(query: str, request_id: str) -> ValidationResult:
    """Validate query doesn't attempt circumvention (convenience function).

    Args:
        query: SQL query to validate
        request_id: Unique identifier for this validation request

    Returns:
        ValidationResult indicating success or failure
    """
    enforcer = SQLEnforcer()
    return enforcer.validate_no_circumvention(query, request_id)


def wrap_query(query: str, min_patient_count: int = MIN_PATIENT_COUNT) -> str:
    """Wrap query with enforcement (convenience function).

    Args:
        query: Validated SQL query
        min_patient_count: Minimum patient count threshold

    Returns:
        Wrapped query with threshold enforcement
    """
    enforcer = SQLEnforcer(min_patient_count)
    return enforcer.wrap_query(query)
