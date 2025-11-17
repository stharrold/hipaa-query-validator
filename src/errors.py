"""Error taxonomy for HIPAA Query Validator.

This module defines the exception hierarchy and error codes (E001-E899)
used throughout the validation system. Each error includes educational
guidance to help users understand and fix issues.
"""

from typing import Set


class ValidationError(Exception):
    """Base exception for all validation errors.

    Attributes:
        code: Error code (E001-E899)
        message: Human-readable error message
        layer: Validation layer that raised the error
        details: Additional context-specific details
    """

    def __init__(
        self,
        code: str,
        message: str,
        layer: str,
        details: dict | None = None,
    ) -> None:
        """Initialize validation error.

        Args:
            code: Error code (e.g., 'E001')
            message: Error message
            layer: Validation layer name
            details: Optional additional details
        """
        self.code = code
        self.message = message
        self.layer = layer
        self.details = details or {}
        super().__init__(f"[{code}] {message}")


# Layer 0: ASCII Input Validation Errors (E001-E099)


class ASCIIValidationError(ValidationError):
    """Base class for ASCII input validation errors."""

    def __init__(self, code: str, message: str, details: dict | None = None) -> None:
        """Initialize ASCII validation error."""
        super().__init__(code, message, "ascii_input", details)


class NonASCIICharacterError(ASCIIValidationError):
    """Error E001: Non-ASCII character detected in input."""

    def __init__(self, position: int, character: str, code_point: int) -> None:
        """Initialize non-ASCII character error.

        Args:
            position: Character position in input string
            character: The non-ASCII character found
            code_point: Unicode code point of the character
        """
        message = (
            f"Non-ASCII character detected at position {position}: "
            f"'{character}' (U+{code_point:04X})"
        )
        details = {"position": position, "character": character, "code_point": code_point}
        super().__init__("E001", message, details)


class InvalidControlCharacterError(ASCIIValidationError):
    """Error E002: Invalid control character detected (not newline, tab, or carriage return)."""

    def __init__(self, position: int, code_point: int) -> None:
        """Initialize invalid control character error.

        Args:
            position: Character position in input string
            code_point: Code point of the invalid control character
        """
        message = (
            f"Invalid control character at position {position}: U+{code_point:04X}. "
            f"Only newline (\\n), carriage return (\\r), and tab (\\t) are allowed."
        )
        details = {"position": position, "code_point": code_point}
        super().__init__("E002", message, details)


class EmptyQueryError(ASCIIValidationError):
    """Error E003: Empty or whitespace-only query."""

    def __init__(self) -> None:
        """Initialize empty query error."""
        message = "Query is empty or contains only whitespace"
        super().__init__("E003", message, {})


# Layer 2: PHI Column Validation Errors (E201-E299)


class PHIValidationError(ValidationError):
    """Base class for PHI column validation errors."""

    def __init__(self, code: str, message: str, details: dict | None = None) -> None:
        """Initialize PHI validation error."""
        super().__init__(code, message, "phi", details)


class DirectPHIIdentifierError(PHIValidationError):
    """Error E201: Direct PHI identifier detected in query."""

    def __init__(self, column_name: str, identifier_type: str, clause: str) -> None:
        """Initialize direct PHI identifier error.

        Args:
            column_name: Name of the PHI column
            identifier_type: Type of PHI identifier (e.g., 'patient_name', 'ssn')
            clause: SQL clause where it was found (SELECT, WHERE, etc.)
        """
        message = (
            f"Direct PHI identifier '{column_name}' ({identifier_type}) "
            f"detected in {clause} clause"
        )
        details = {
            "column_name": column_name,
            "identifier_type": identifier_type,
            "clause": clause,
        }
        super().__init__("E201", message, details)


class GeographicPHIError(PHIValidationError):
    """Error E202: Prohibited geographic subdivision detected."""

    def __init__(self, column_name: str, clause: str) -> None:
        """Initialize geographic PHI error.

        Args:
            column_name: Name of the geographic column
            clause: SQL clause where it was found
        """
        message = (
            f"Prohibited geographic identifier '{column_name}' detected in {clause} clause. "
            f"Only state-level or larger geographic divisions are allowed."
        )
        details = {"column_name": column_name, "clause": clause}
        super().__init__("E202", message, details)


class DatePHIError(PHIValidationError):
    """Error E203: Prohibited date element detected (not year)."""

    def __init__(self, column_name: str, clause: str) -> None:
        """Initialize date PHI error.

        Args:
            column_name: Name of the date column
            clause: SQL clause where it was found
        """
        message = (
            f"Prohibited date element '{column_name}' detected in {clause} clause. "
            f"Only year is allowed; month and day must be excluded."
        )
        details = {"column_name": column_name, "clause": clause}
        super().__init__("E203", message, details)


class SelectStarError(PHIValidationError):
    """Error E204: SELECT * is prohibited."""

    def __init__(self) -> None:
        """Initialize SELECT * error."""
        message = "SELECT * is prohibited. You must explicitly list allowed columns."
        super().__init__("E204", message, {})


# Layer 3: Aggregation Validation Errors (E301-E399)


class AggregationValidationError(ValidationError):
    """Base class for aggregation validation errors."""

    def __init__(self, code: str, message: str, details: dict | None = None) -> None:
        """Initialize aggregation validation error."""
        super().__init__(code, message, "aggregation", details)


class MissingGroupByError(AggregationValidationError):
    """Error E301: GROUP BY clause required but missing."""

    def __init__(self) -> None:
        """Initialize missing GROUP BY error."""
        message = (
            "GROUP BY clause is required for all queries except global aggregates. "
            "You must group by at least one non-PHI dimension."
        )
        super().__init__("E301", message, {})


class MissingPatientCountError(AggregationValidationError):
    """Error E302: Required patient count column missing."""

    def __init__(self) -> None:
        """Initialize missing patient count error."""
        message = (
            "Required patient count column missing. "
            "You must include: COUNT(DISTINCT person_id) AS Count_Patients"
        )
        super().__init__("E302", message, {})


class InvalidPatientCountSyntaxError(AggregationValidationError):
    """Error E303: Patient count syntax is incorrect."""

    def __init__(self, found_syntax: str) -> None:
        """Initialize invalid patient count syntax error.

        Args:
            found_syntax: The incorrect syntax that was found
        """
        message = (
            f"Invalid patient count syntax: '{found_syntax}'. "
            f"Required syntax: COUNT(DISTINCT person_id) AS Count_Patients"
        )
        details = {"found_syntax": found_syntax}
        super().__init__("E303", message, details)


class AggregateInNonSelectError(AggregationValidationError):
    """Error E304: Aggregate function found outside SELECT clause."""

    def __init__(self, clause: str, function: str) -> None:
        """Initialize aggregate in non-SELECT error.

        Args:
            clause: The clause where aggregate was found (WHERE, GROUP BY, etc.)
            function: The aggregate function found
        """
        message = (
            f"Aggregate function '{function}' found in {clause} clause. "
            f"Aggregate functions are only allowed in SELECT clause."
        )
        details = {"clause": clause, "function": function}
        super().__init__("E304", message, details)


class InvalidGroupByColumnError(AggregationValidationError):
    """Error E305: Invalid column in GROUP BY clause."""

    def __init__(self, column_name: str, reason: str) -> None:
        """Initialize invalid GROUP BY column error.

        Args:
            column_name: Name of the invalid column
            reason: Reason why the column is invalid
        """
        message = f"Invalid column '{column_name}' in GROUP BY clause: {reason}"
        details = {"column_name": column_name, "reason": reason}
        super().__init__("E305", message, details)


# Layer 4: SQL Enforcement Errors (E401-E499)


class EnforcementError(ValidationError):
    """Base class for SQL enforcement errors."""

    def __init__(self, code: str, message: str, details: dict | None = None) -> None:
        """Initialize enforcement error."""
        super().__init__(code, message, "enforcement", details)


class SubqueryNotAllowedError(EnforcementError):
    """Error E401: Subqueries not allowed (prevents wrapper bypass)."""

    def __init__(self) -> None:
        """Initialize subquery not allowed error."""
        message = (
            "Subqueries are not allowed. This prevents circumvention of the "
            "minimum patient count threshold."
        )
        super().__init__("E401", message, {})


class CTENotAllowedError(EnforcementError):
    """Error E402: Common Table Expressions (CTEs) not allowed."""

    def __init__(self) -> None:
        """Initialize CTE not allowed error."""
        message = (
            "Common Table Expressions (WITH clauses) are not allowed. "
            "This prevents circumvention of security controls."
        )
        super().__init__("E402", message, {})


# Layer 1: Schema Validation Errors (E101-E199)


class SchemaValidationError(ValidationError):
    """Base class for schema validation errors."""

    def __init__(self, code: str, message: str, details: dict | None = None) -> None:
        """Initialize schema validation error."""
        super().__init__(code, message, "schema", details)


class UnknownTableError(SchemaValidationError):
    """Error E101: Table not found in approved schema."""

    def __init__(self, table_name: str, schema: str, valid_tables: Set[str] | None = None) -> None:
        """Initialize unknown table error.

        Args:
            table_name: Name of the unknown table
            schema: Schema version (e.g., 'OMOP 5.4')
            valid_tables: Set of valid table names for educational guidance
        """
        # Build educational guidance
        guidance_lines = [
            f"Table '{table_name}' is not found in the {schema} schema.\n",
            "This query cannot be validated because it references an unknown or unauthorized table.\n",
        ]

        if valid_tables and len(valid_tables) > 0:
            # Show sample of valid tables
            sample_tables = sorted(list(valid_tables))[:10]
            tables_str = ", ".join(sample_tables)
            if len(valid_tables) > 10:
                tables_str += f", ... ({len(valid_tables)} total tables)"

            guidance_lines.append(f"\nValid {schema} tables include:")
            guidance_lines.append(f"{tables_str}\n")

            # Common OMOP tables
            guidance_lines.append("\nCommon OMOP CDM tables:")
            guidance_lines.append("- person (patient demographics)")
            guidance_lines.append("- condition_occurrence (diagnoses)")
            guidance_lines.append("- drug_exposure (medications)")
            guidance_lines.append("- visit_occurrence (encounters)")
            guidance_lines.append("- measurement (lab results)")
            guidance_lines.append("- observation (clinical observations)")

        guidance_lines.append("\n\nPlease verify the table name and try again.")

        message = "".join(guidance_lines)
        details = {"table_name": table_name, "schema": schema}
        super().__init__("E101", message, details)


class UnknownColumnError(SchemaValidationError):
    """Error E102: Column not found in table schema."""

    def __init__(
        self, column_name: str, table_name: str, schema: str, valid_columns: Set[str] | None = None
    ) -> None:
        """Initialize unknown column error.

        Args:
            column_name: Name of the unknown column
            table_name: Name of the table
            schema: Schema version
            valid_columns: Set of valid column names for educational guidance
        """
        # Build educational guidance
        guidance_lines = [
            f"Column '{column_name}' is not found in table '{table_name}' ({schema}).\n",
            "This query cannot be validated because it references an unknown column.\n",
        ]

        if valid_columns and len(valid_columns) > 0:
            # Show sample of valid columns
            sample_columns = sorted(list(valid_columns))[:15]
            columns_str = ", ".join(sample_columns)
            if len(valid_columns) > 15:
                columns_str += f", ... ({len(valid_columns)} total columns)"

            guidance_lines.append(f"\nValid columns for '{table_name}':")
            guidance_lines.append(f"{columns_str}")

        guidance_lines.append("\n\nPlease verify the column name and try again.")

        message = "".join(guidance_lines)
        details = {"column_name": column_name, "table_name": table_name, "schema": schema}
        super().__init__("E102", message, details)


class SchemaNotLoadedError(SchemaValidationError):
    """Error E103: Schema configuration not loaded."""

    def __init__(self) -> None:
        """Initialize schema not loaded error."""
        message = (
            "Schema configuration not loaded.\n\n"
            "The OMOP schema definition file could not be loaded. "
            "This is a system configuration error.\n\n"
            "Please contact your system administrator."
        )
        super().__init__("E103", message, {})


# System Errors (E801-E899)


class SystemError(ValidationError):
    """Base class for system-level errors."""

    def __init__(self, code: str, message: str, details: dict | None = None) -> None:
        """Initialize system error."""
        super().__init__(code, message, "system", details)


class ConfigurationError(SystemError):
    """Error E801: Configuration file error."""

    def __init__(self, config_file: str, reason: str) -> None:
        """Initialize configuration error.

        Args:
            config_file: Path to configuration file
            reason: Reason for configuration error
        """
        message = f"Configuration error in '{config_file}': {reason}"
        details = {"config_file": config_file, "reason": reason}
        super().__init__("E801", message, details)


class ParsingError(SystemError):
    """Error E802: SQL parsing error."""

    def __init__(self, reason: str) -> None:
        """Initialize parsing error.

        Args:
            reason: Reason for parsing failure
        """
        message = f"SQL parsing error: {reason}"
        details = {"reason": reason}
        super().__init__("E802", message, details)
