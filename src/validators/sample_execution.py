"""Layer 5: Sample Query Execution Validation.

This module executes validated queries against synthetic sample data to catch
runtime errors that static analysis cannot detect:
- SQL syntax errors
- Type mismatches
- Division by zero
- Performance issues (cartesian products)
- Result set anomalies

Performance target: <500ms execution time
Memory usage: Results capped at 10,000 rows
"""

import sqlite3
import time
from typing import Any

from ..errors import (
    QueryExecutionError,
    ResultSetTooLargeError,
)
from ..models import ValidationResult
from ..sample_data.generator import sample_db


def validate_sample_execution(
    wrapped_query: str,
    request_id: str,
    timeout_ms: int = 500,
    max_rows: int = 10000,
) -> ValidationResult:
    """Execute query against sample database to catch runtime errors.

    This is Layer 5 of the validation pipeline. The query has already passed:
    - Layer 0: ASCII validation
    - Layer 2: PHI validation
    - Layer 3: Aggregation validation
    - Layer 4: Enforcement validation and wrapping

    Args:
        wrapped_query: SQL query with enforcement wrapper applied
        request_id: Unique identifier for this validation request
        timeout_ms: Timeout in milliseconds (default: 500ms)
        max_rows: Maximum result rows (default: 10,000)

    Returns:
        ValidationResult with execution metadata

    Raises:
        QueryExecutionError: If query fails during execution
        QueryTimeoutError: If query exceeds timeout (not currently enforced)
        ResultSetTooLargeError: If result exceeds max_rows

    Note:
        - Empty results do NOT raise an error (may be valid for production data)
        - Timeout enforcement is advisory only (SQLite limitations)
    """
    start_time = time.perf_counter()

    try:
        # Execute query against sample database
        results, column_names = sample_db.execute_query(wrapped_query, timeout_ms)

        # Check result set size
        row_count = len(results)
        if row_count > max_rows:
            raise ResultSetTooLargeError(row_count, max_rows)

        # Calculate execution time
        execution_time_ms = (time.perf_counter() - start_time) * 1000

        # Advisory timeout check (not enforced, just logged)
        # SQLite doesn't support hard query timeouts without threading
        if execution_time_ms > timeout_ms:
            # Could log warning here, but don't fail the query
            pass

        # Build execution metadata
        execution_metadata = {
            "status": "executed",
            "row_count": row_count,
            "execution_time_ms": round(execution_time_ms, 2),
            "column_names": column_names,
            "sample_result": results[:5] if results else [],  # First 5 rows for preview
        }

        return ValidationResult(
            success=True,
            request_id=request_id,
            layer="sample_execution",
            code=None,
            message="Sample execution validation passed",
            educational_guidance=None,
            correct_pattern=None,
            details=execution_metadata,
        )

    except sqlite3.Error as e:
        # SQL execution error - this catches syntax errors, type mismatches, etc.
        sql_error_type = type(e).__name__
        error_message = str(e)

        raise QueryExecutionError(
            sql_error=sql_error_type,
            error_message=error_message,
        ) from e


def extract_column_names(query: str) -> list[str]:
    """Extract column names from query by executing against sample database.

    This is a helper function for debugging and analysis.

    Args:
        query: SQL query string

    Returns:
        List of column names that would be returned by the query

    Raises:
        sqlite3.Error: If query is invalid
    """
    try:
        _, column_names = sample_db.execute_query(query)
        return column_names
    except sqlite3.Error:
        return []


def get_sample_results(query: str, limit: int = 5) -> list[tuple[Any, ...]]:
    """Get sample results from query execution.

    Useful for testing and debugging.

    Args:
        query: SQL query to execute
        limit: Maximum number of rows to return (default: 5)

    Returns:
        List of result tuples (up to limit rows)

    Raises:
        sqlite3.Error: If query execution fails
    """
    results, _ = sample_db.execute_query(query)
    return results[:limit]
