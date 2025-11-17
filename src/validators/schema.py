"""Layer 1: OMOP Schema Validation.

Validates that SQL queries only reference tables and columns that exist
in the configured OMOP CDM schema. This layer prevents errors from invalid
references and provides security by blocking unauthorized table access.

Performance target: <2ms overhead for typical queries
"""

import sqlparse  # type: ignore[import-untyped]
from sqlparse.sql import (  # type: ignore[import-untyped]
    Function,
    Identifier,
    IdentifierList,
    Statement,
    Where,
)
from sqlparse.tokens import Keyword  # type: ignore[import-untyped]

from ..errors import SchemaNotLoadedError, UnknownColumnError, UnknownTableError
from ..models import ValidationResult
from ..schemas.loader import schema_cache

# Module-level configuration for error verbosity
_VERBOSE_ERRORS = True  # Default: include suggestions


def set_error_verbosity(verbose: bool) -> None:
    """Configure whether errors include suggestions for valid tables/columns.

    Args:
        verbose: If True, include suggestions. If False, omit for production.
    """
    global _VERBOSE_ERRORS
    _VERBOSE_ERRORS = verbose


def get_error_verbosity() -> bool:
    """Get current error verbosity setting.

    Returns:
        True if errors include suggestions, False otherwise
    """
    return _VERBOSE_ERRORS


def validate_schema(query: str, request_id: str) -> ValidationResult:
    """Validate query against OMOP schema.

    This is Layer 1 of the validation pipeline and validates that all
    tables and columns referenced in the query exist in the OMOP CDM schema.

    Args:
        query: SQL query to validate
        request_id: Unique identifier for this validation request

    Returns:
        ValidationResult indicating success or failure

    Raises:
        SchemaNotLoadedError: If schema configuration not loaded
        UnknownTableError: If query references non-existent table
        UnknownColumnError: If query references non-existent column
    """
    # Verify schema is loaded
    if len(schema_cache.get_valid_tables()) == 0:
        raise SchemaNotLoadedError()

    # Parse query
    parsed = sqlparse.parse(query)
    if not parsed:
        # Empty query - let other validators handle this
        return ValidationResult(
            success=True,
            request_id=request_id,
            layer="schema",
            message="Schema validation passed (no tokens to validate)",
        )

    # Validate each statement
    for statement in parsed:
        validator = SchemaValidator(request_id)
        validator.validate(statement)

    return ValidationResult(
        success=True,
        request_id=request_id,
        layer="schema",
        code=None,
        message="Schema validation passed - all table and column references are valid",
        educational_guidance=None,
        correct_pattern=None,
    )


class SchemaValidator:
    """Validates SQL query against OMOP schema.

    This validator uses a two-pass approach:
    1. Extract all table references (FROM, JOIN clauses)
    2. Validate all column references against known tables

    Handles:
    - Table aliases (e.g., "person p")
    - Qualified column references (e.g., "p.person_id")
    - Schema-qualified tables (e.g., "dbo.person")
    """

    def __init__(self, request_id: str, max_recursion_depth: int = 100):
        """Initialize schema validator.

        Args:
            request_id: Unique identifier for this validation request
            max_recursion_depth: Maximum recursion depth for token traversal
        """
        self.request_id = request_id
        self.table_aliases: dict[str, str] = {}  # alias -> real_table_name
        self.tables_in_query: set[str] = set()
        self.max_recursion_depth = max_recursion_depth

    def validate(self, statement: Statement) -> None:
        """Main validation entry point.

        Args:
            statement: Parsed SQL statement to validate

        Raises:
            UnknownTableError: If table reference is invalid
            UnknownColumnError: If column reference is invalid
        """
        # Pass 1: Extract all table references
        self._extract_tables(statement)

        # Validate all tables exist
        for table_name in self.tables_in_query:
            if not schema_cache.is_valid_table(table_name):
                raise UnknownTableError(
                    table_name=table_name,
                    schema="OMOP CDM v5.4",
                    valid_tables=schema_cache.get_valid_tables() if _VERBOSE_ERRORS else set(),
                )

        # Pass 2: Validate column references
        self._validate_columns(statement)

    def _extract_tables(self, statement: Statement) -> None:
        """Extract all table references from FROM and JOIN clauses.

        Args:
            statement: Parsed SQL statement
        """
        from_seen = False
        in_join = False

        for token in statement.tokens:
            # Skip whitespace
            if token.is_whitespace:
                continue

            # WHERE is packaged as a Where object, stop processing tables
            if isinstance(token, Where):
                from_seen = False
                in_join = False
                continue

            # Stop at GROUP BY/ORDER BY/HAVING/LIMIT (keyword-based)
            if token.ttype is Keyword and token.value.upper() in (
                "WHERE",
                "GROUP",
                "ORDER",
                "HAVING",
                "LIMIT",
            ):
                from_seen = False
                in_join = False
                continue

            # Track when we're in FROM clause
            if token.ttype is Keyword and token.value.upper() == "FROM":
                from_seen = True
                continue

            # Track JOIN keywords
            if token.ttype is Keyword and "JOIN" in token.value.upper():
                in_join = True
                from_seen = True  # Treat JOIN like FROM
                continue

            # Process table references after FROM or JOIN
            if from_seen or in_join:
                if isinstance(token, Identifier):
                    self._process_table_identifier(token)
                    # Reset flags after processing single table
                    if not in_join:
                        # FROM has only one table, reset
                        from_seen = False
                    in_join = False
                elif isinstance(token, IdentifierList):
                    for identifier in token.get_identifiers():
                        self._process_table_identifier(identifier)
                    # Reset flags after processing table list
                    from_seen = False
                    in_join = False

    def _process_table_identifier(self, identifier: Identifier) -> None:
        """Process a table identifier (handles aliases and schema prefixes).

        Args:
            identifier: SQL identifier for a table
        """
        # Get real table name (before AS alias)
        table_name = identifier.get_real_name()

        if table_name:
            # Remove schema qualification (e.g., "dbo.person" -> "person")
            if "." in table_name:
                table_name = table_name.split(".")[-1]

            # Store table name in lowercase for case-insensitive comparison
            self.tables_in_query.add(table_name.lower())

            # Store alias mapping if present (both in lowercase)
            alias = identifier.get_alias()
            if alias:
                self.table_aliases[alias.lower()] = table_name.lower()

    def _validate_columns(self, statement: Statement) -> None:
        """Validate all column references in the statement.

        Args:
            statement: Parsed SQL statement

        Raises:
            UnknownColumnError: If column reference is invalid
        """
        from_seen = False
        in_join = False

        for token in statement.tokens:
            # Skip whitespace
            if token.is_whitespace:
                continue

            # WHERE is packaged as a Where object, validate its contents
            if isinstance(token, Where):
                from_seen = False
                in_join = False
                self._validate_columns_recursive(token, depth=0)
                continue

            # Stop at GROUP BY/ORDER BY/HAVING/LIMIT (keyword-based)
            if token.ttype is Keyword and token.value.upper() in (
                "WHERE",
                "GROUP",
                "ORDER",
                "HAVING",
                "LIMIT",
            ):
                from_seen = False
                in_join = False
                continue

            # Track when we're in FROM clause
            if token.ttype is Keyword and token.value.upper() == "FROM":
                from_seen = True
                continue

            # Track JOIN keywords
            if token.ttype is Keyword and "JOIN" in token.value.upper():
                in_join = True
                from_seen = True
                continue

            # Skip table identifiers in FROM/JOIN clauses
            if from_seen or in_join:
                if isinstance(token, Identifier) or isinstance(token, IdentifierList):
                    # These are table references, not columns - skip
                    if not in_join:
                        from_seen = False
                    in_join = False
                    continue

            # Validate column identifiers (not in FROM/JOIN)
            if isinstance(token, IdentifierList):
                # SELECT column1, column2, ...
                for identifier in token.get_identifiers():
                    self._validate_column_identifier(identifier)
            elif isinstance(token, Identifier):
                self._validate_column_identifier(token)
            elif isinstance(token, Function):
                # COUNT(column_name), etc.
                self._validate_function_columns(token)
            elif hasattr(token, "tokens"):
                # Recurse into sub-tokens (ON clause, etc.)
                self._validate_columns_recursive(token, depth=0)

    def _validate_column_identifier(self, identifier: Identifier) -> None:
        """Validate a single column identifier.

        Args:
            identifier: SQL identifier for a column

        Raises:
            UnknownColumnError: If column reference is invalid
        """
        # Get the actual column name (handle aliases)
        if identifier.has_alias():
            # For "column AS alias", validate the real column name
            real_name = identifier.get_real_name()
            if real_name and "." in real_name:
                self._validate_qualified_column(real_name)
        else:
            # Simple column reference or qualified (table.column)
            column_str = str(identifier).strip()
            if "." in column_str:
                self._validate_qualified_column(column_str)
            else:
                # Validate unqualified column against all tables in query
                self._validate_unqualified_column(column_str)

    def _validate_qualified_column(self, column_ref: str) -> None:
        """Validate a qualified column reference (table.column).

        Args:
            column_ref: Column reference string (e.g., "person.person_id")

        Raises:
            UnknownColumnError: If column reference is invalid
        """
        parts = column_ref.split(".")
        if len(parts) == 2:
            table_or_alias, column = parts

            # Resolve alias to real table name (case-insensitive)
            table_name_lower = self.table_aliases.get(
                table_or_alias.lower(), table_or_alias.lower()
            )

            # Validate column exists in table (only if table is in query)
            if table_name_lower in self.tables_in_query:
                if not schema_cache.is_valid_column(table_name_lower, column):
                    raise UnknownColumnError(
                        column_name=column,
                        table_name=table_name_lower,
                        schema="OMOP CDM v5.4",
                        valid_columns=(
                            schema_cache.get_valid_columns(table_name_lower)
                            if _VERBOSE_ERRORS
                            else set()
                        ),
                    )

    def _validate_unqualified_column(self, column_name: str) -> None:
        """Validate unqualified column exists in at least one query table.

        Args:
            column_name: Column name to validate

        Raises:
            UnknownColumnError: If column not found in any query table
        """
        # Skip validation if no tables in query yet
        if not self.tables_in_query:
            return

        # Skip validation for SQL keywords and common function names
        # These are not column references
        sql_keywords = {
            "count",
            "sum",
            "avg",
            "min",
            "max",
            "distinct",
            "as",
            "asc",
            "desc",
            "null",
            "true",
            "false",
        }
        if column_name.lower() in sql_keywords:
            return

        # Check if column exists in any table
        column_lower = column_name.lower()
        for table_name in self.tables_in_query:
            if schema_cache.is_valid_column(table_name, column_lower):
                return  # Valid - found in at least one table

        # Column not found in any query table
        raise UnknownColumnError(
            column_name=column_name,
            table_name=f"any of [{', '.join(sorted(self.tables_in_query))}]",
            schema="OMOP CDM v5.4",
            valid_columns=set(),  # Cannot provide specific columns for multiple tables
        )

    def _validate_function_columns(self, function: Function) -> None:
        """Validate columns inside functions (e.g., COUNT(person_id)).

        Args:
            function: Function token containing column references
        """
        for token in function.tokens:
            if isinstance(token, Identifier):
                self._validate_column_identifier(token)
            elif isinstance(token, IdentifierList):
                for identifier in token.get_identifiers():
                    if isinstance(identifier, Identifier):
                        self._validate_column_identifier(identifier)

    def _validate_columns_recursive(self, token: object, depth: int = 0) -> None:
        """Recursively validate columns in nested structures.

        Args:
            token: Token to recursively validate
            depth: Current recursion depth

        Raises:
            ValueError: If recursion depth exceeds maximum
        """
        if depth > self.max_recursion_depth:
            raise ValueError(
                f"SQL structure too deeply nested (max depth: {self.max_recursion_depth}). "
                f"This may indicate malformed SQL or a denial-of-service attempt."
            )

        if hasattr(token, "tokens"):
            for subtoken in token.tokens:
                if isinstance(subtoken, Identifier):
                    self._validate_column_identifier(subtoken)
                elif isinstance(subtoken, IdentifierList):
                    for identifier in subtoken.get_identifiers():
                        if isinstance(identifier, Identifier):
                            self._validate_column_identifier(identifier)
                elif isinstance(subtoken, Function):
                    self._validate_function_columns(subtoken)
                elif hasattr(subtoken, "tokens"):
                    self._validate_columns_recursive(subtoken, depth + 1)
