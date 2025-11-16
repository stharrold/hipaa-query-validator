"""Layer 3: Aggregation Enforcement.

This module enforces HIPAA-compliant aggregation requirements:
1. Require GROUP BY clause (except for global aggregates)
2. Require exact syntax: COUNT(DISTINCT person_id) AS Count_Patients
3. Validate aggregate functions only in SELECT clause
4. Ensure proper de-identification through aggregation

Aggregation is the primary mechanism for de-identification in this system.
The minimum threshold of 20,000 patients is enforced separately in Layer 4.
"""

import re
from typing import List, Optional, Set, Tuple

import sqlparse
from sqlparse.sql import Function, Identifier, IdentifierList, Parenthesis, Token
from sqlparse.tokens import Keyword

from ..errors import (
    AggregateInNonSelectError,
    InvalidGroupByColumnError,
    InvalidPatientCountSyntaxError,
    MissingGroupByError,
    MissingPatientCountError,
)
from ..models import ValidationResult


# Required patient count pattern (exact match)
# Accepts: person_id, p.person_id, person.person_id, etc.
# Note: SQL keywords are case-insensitive, but alias must be exactly "Count_Patients"
REQUIRED_PATIENT_COUNT_PATTERN_KEYWORDS = re.compile(
    r"COUNT\s*\(\s*DISTINCT\s+(?:\w+\.)?person_id\s*\)\s+AS\s+(\w+)", re.IGNORECASE
)
# Exact alias match (case-sensitive)
REQUIRED_ALIAS = "Count_Patients"

# Aggregate functions to detect
AGGREGATE_FUNCTIONS = {"COUNT", "SUM", "AVG", "MIN", "MAX", "STDDEV", "VARIANCE"}


class AggregationValidator:
    """Validator for aggregation requirements."""

    def __init__(self) -> None:
        """Initialize aggregation validator."""
        self.has_group_by = False
        self.has_patient_count = False
        self.select_aggregates: List[str] = []
        self.select_regular_columns: List[str] = []  # Non-aggregate columns in SELECT
        self.non_select_aggregates: List[Tuple[str, str]] = []  # (function, clause)
        self.group_by_columns: List[str] = []

    def validate_aggregation(self, query: str, request_id: str) -> ValidationResult:
        """Validate query aggregation requirements.

        Args:
            query: SQL query to validate
            request_id: Unique identifier for this validation request

        Returns:
            ValidationResult indicating success or failure

        Raises:
            MissingGroupByError: If GROUP BY clause missing (and not global aggregate)
            MissingPatientCountError: If required patient count column missing
            InvalidPatientCountSyntaxError: If patient count syntax is incorrect
            AggregateInNonSelectError: If aggregate function in non-SELECT clause
        """
        # Reset state
        self.has_group_by = False
        self.has_patient_count = False
        self.select_aggregates = []
        self.select_regular_columns = []
        self.non_select_aggregates = []
        self.group_by_columns = []

        # Parse the SQL query
        parsed = sqlparse.parse(query)
        if not parsed:
            # Empty query - let other validators handle this
            return ValidationResult(
                success=True,
                request_id=request_id,
                layer="aggregation",
                message="Aggregation validation passed (no statements to validate)",
            )

        # Validate each statement
        for statement in parsed:
            self._analyze_statement(statement)

        # Check for required patient count
        if not self._check_patient_count_syntax(query):
            raise MissingPatientCountError()

        # Check for GROUP BY (required unless it's a global aggregate)
        if not self.has_group_by and not self._is_global_aggregate():
            raise MissingGroupByError()

        # Check that aggregates only appear in SELECT
        if self.non_select_aggregates:
            function, clause = self.non_select_aggregates[0]
            raise AggregateInNonSelectError(clause=clause, function=function)

        return ValidationResult(
            success=True,
            request_id=request_id,
            layer="aggregation",
            code=None,
            message="Aggregation validation passed",
            educational_guidance=None,
            correct_pattern=None,
        )

    def _analyze_statement(self, statement: sqlparse.sql.Statement) -> None:
        """Analyze a SQL statement for aggregation patterns.

        Args:
            statement: Parsed SQL statement
        """
        # Check for GROUP BY in the flattened token string (more reliable)
        statement_str = str(statement).upper()
        # Use regex to handle any amount of whitespace between GROUP and BY
        if re.search(r'GROUP\s+BY', statement_str):
            self.has_group_by = True

        current_clause = None

        for token in statement.tokens:
            # Skip whitespace and punctuation
            if token.is_whitespace or token.ttype is sqlparse.tokens.Punctuation:
                continue

            # Track which clause we're in (check if token is a keyword)
            if token.ttype is not None and token.ttype in sqlparse.tokens.Keyword:
                keyword = token.value.upper()
                if keyword == "SELECT":
                    current_clause = "SELECT"
                elif keyword in ("FROM", "WHERE", "HAVING", "ORDER"):
                    current_clause = keyword
                elif keyword == "GROUP":
                    # GROUP BY is typically two tokens
                    current_clause = "GROUP BY"
                    self.has_group_by = True
                elif keyword == "BY" and current_clause == "GROUP":
                    # This is part of GROUP BY
                    current_clause = "GROUP BY"
                    self.has_group_by = True
                elif keyword in ("JOIN", "INNER", "LEFT", "RIGHT", "OUTER"):
                    current_clause = "JOIN"

            # Check for aggregate functions
            if isinstance(token, Function):
                self._check_function(token, current_clause or "UNKNOWN")
            elif isinstance(token, IdentifierList):
                for item in token.get_identifiers():
                    if isinstance(item, Function):
                        self._check_function(item, current_clause or "UNKNOWN")
                    elif isinstance(item, Identifier):
                        # Check if this identifier contains a function (aliased aggregate)
                        has_function = False
                        if hasattr(item, 'tokens'):
                            for subtoken in item.tokens:
                                if isinstance(subtoken, Function):
                                    self._check_function(subtoken, current_clause or "UNKNOWN")
                                    has_function = True
                                    break
                        if current_clause == "SELECT" and not has_function:
                            # Regular column in SELECT (not an aggregate)
                            self.select_regular_columns.append(str(item).strip())
                        elif current_clause == "GROUP BY":
                            self.group_by_columns.append(str(item).strip())
                    elif current_clause == "SELECT":
                        # Other token types in SELECT (shouldn't happen often)
                        self.select_regular_columns.append(str(item).strip())
                    elif current_clause == "GROUP BY":
                        self.group_by_columns.append(str(item).strip())
            elif isinstance(token, Identifier):
                if current_clause == "SELECT":
                    # Check if this identifier contains a function (aliased aggregate)
                    has_function = False
                    if hasattr(token, 'tokens'):
                        for subtoken in token.tokens:
                            if isinstance(subtoken, Function):
                                self._check_function(subtoken, current_clause)
                                has_function = True
                                break
                    # Only add to regular columns if it's not a function
                    if not has_function:
                        self.select_regular_columns.append(str(token).strip())
                elif current_clause == "GROUP BY":
                    self.group_by_columns.append(str(token).strip())

    def _check_function(self, func: Function, clause: str) -> None:
        """Check if a function is an aggregate and in which clause.

        Args:
            func: SQL function token
            clause: SQL clause where function appears
        """
        func_name = func.get_name()
        if not func_name:
            return

        func_upper = func_name.upper()

        if func_upper in AGGREGATE_FUNCTIONS:
            if clause == "SELECT":
                self.select_aggregates.append(str(func))
            else:
                self.non_select_aggregates.append((str(func), clause))

    def _check_patient_count_syntax(self, query: str) -> bool:
        """Check if query contains required patient count with exact syntax.

        Required syntax: COUNT(DISTINCT person_id) AS Count_Patients

        Args:
            query: SQL query string

        Returns:
            True if correct patient count syntax found, False otherwise
        """
        # Normalize whitespace for matching
        normalized_query = " ".join(query.split())

        # Check for pattern match with keywords (case-insensitive)
        match = REQUIRED_PATIENT_COUNT_PATTERN_KEYWORDS.search(normalized_query)
        if match:
            # Check if alias is exactly "Count_Patients" (case-sensitive)
            alias = match.group(1)
            if alias == REQUIRED_ALIAS:
                self.has_patient_count = True
                return True
            else:
                # Correct syntax but wrong alias case
                raise InvalidPatientCountSyntaxError(found_syntax=match.group(0))

        # Check if there's an incorrect patient count syntax
        count_patterns = [
            r"COUNT\s*\(\s*person_id\s*\)",  # Missing DISTINCT
            r"COUNT\s*\(\s*DISTINCT\s+(?:\w+\.)?person_id\s*\)",  # Missing AS
        ]

        for pattern in count_patterns:
            if re.search(pattern, normalized_query, re.IGNORECASE):
                # Found incorrect syntax - raise specific error
                found = re.search(pattern, normalized_query, re.IGNORECASE).group(0)
                raise InvalidPatientCountSyntaxError(found_syntax=found)

        return False

    def _is_global_aggregate(self) -> bool:
        """Check if this is a global aggregate query (no GROUP BY needed).

        A global aggregate query is one that aggregates across the entire
        dataset without grouping by any dimensions. It should ONLY have
        aggregate functions in SELECT, not regular columns.

        Returns:
            True if this is a global aggregate, False otherwise
        """
        # Global aggregate if:
        # 1. We have aggregates (including patient count)
        # 2. No GROUP BY clause
        # 3. NO regular (non-aggregate) columns in SELECT
        has_aggregates = len(self.select_aggregates) > 0 or self.has_patient_count
        has_no_regular_columns = len(self.select_regular_columns) == 0
        return has_aggregates and not self.has_group_by and has_no_regular_columns


def validate_aggregation(query: str, request_id: str) -> ValidationResult:
    """Validate query aggregation requirements (convenience function).

    Args:
        query: SQL query to validate
        request_id: Unique identifier for this validation request

    Returns:
        ValidationResult indicating success or failure
    """
    validator = AggregationValidator()
    return validator.validate_aggregation(query, request_id)


def extract_group_by_columns(query: str) -> List[str]:
    """Extract column names from GROUP BY clause.

    Useful for debugging and analysis.

    Args:
        query: SQL query string

    Returns:
        List of column names in GROUP BY clause
    """
    validator = AggregationValidator()
    parsed = sqlparse.parse(query)

    for statement in parsed:
        validator._analyze_statement(statement)

    # If token-based extraction didn't work, try regex fallback
    if not validator.group_by_columns:
        # Extract GROUP BY columns using regex
        match = re.search(r'GROUP\s+BY\s+([^;]+?)(?:$|ORDER|HAVING|LIMIT)',
                         query, re.IGNORECASE | re.DOTALL)
        if match:
            group_by_clause = match.group(1).strip()
            # Split by comma and clean up
            columns = [col.strip() for col in group_by_clause.split(',')]
            return columns

    return validator.group_by_columns


def has_required_patient_count(query: str) -> bool:
    """Check if query has required patient count column.

    Args:
        query: SQL query string

    Returns:
        True if required patient count present, False otherwise
    """
    normalized_query = " ".join(query.split())
    match = REQUIRED_PATIENT_COUNT_PATTERN_KEYWORDS.search(normalized_query)
    if match:
        # Check if alias is exactly "Count_Patients" (case-sensitive)
        alias = match.group(1)
        return alias == REQUIRED_ALIAS
    return False
