"""Layer 8: ASCII Output Validation.

This module implements the final validation layer that checks query results
to ensure output contains only safe ASCII characters and enforces HIPAA
de-identification requirements on actual result data.

This is the last line of defense that validates query execution results before
returning them to users. It catches:
- Unicode-based PHI exposure in output
- Control characters in results
- Threshold violations in actual counts
- Suspicious patterns that may indicate PHI leakage

Performance target: <10ms overhead for typical result sets
Security: Final validation before data leaves the system
"""

import re
from typing import Any

from ..errors import (
    NonASCIIOutputError,
    PatientCountBelowThresholdError,
    TooManyRowsError,
)
from ..models import ValidationResult

# Safe ASCII character set
# - Printable ASCII: 0x20 (space) to 0x7E (~)
# - Allowed whitespace: \n (0x0A), \r (0x0D), \t (0x09)
SAFE_ASCII_CHARS = set(range(0x20, 0x7F)) | {ord("\n"), ord("\r"), ord("\t")}


def validate_ascii_output(
    result_set: list[dict[str, Any]],
    request_id: str,
    min_patient_count: int = 20000,
    max_rows: int = 10000,
) -> ValidationResult:
    """Validate query result set for ASCII-only output and HIPAA compliance.

    This is Layer 8 of the validation pipeline and must be the final
    validation performed after query execution.

    Args:
        result_set: List of result rows (each row is a dict mapping column name to value)
        request_id: Unique identifier for this validation request
        min_patient_count: Minimum patient count threshold (HIPAA Safe Harbor)
        max_rows: Maximum number of rows allowed in result set

    Returns:
        ValidationResult indicating success or failure

    Raises:
        NonASCIIOutputError: If non-ASCII character detected in output
        PatientCountBelowThresholdError: If patient count below threshold
        TooManyRowsError: If result set exceeds row limit

    Performance:
        - Best case: O(n*m) where n is row count, m is avg column value length
        - Target: <10ms overhead for typical result sets
        - Implementation: Single-pass validation with early termination

    Security:
        Protects against:
        - Unicode encoding attacks in output
        - PHI exposure via non-ASCII characters
        - Threshold bypass in execution results
        - Exfiltration via large result sets
    """
    # Check row count limit
    row_count = len(result_set)
    if row_count > max_rows:
        raise TooManyRowsError(row_count, max_rows)

    # Empty result set is valid
    if row_count == 0:
        return ValidationResult(
            success=True,
            request_id=request_id,
            layer="ascii_output",
            code=None,
            message="ASCII output validation passed (empty result set)",
            educational_guidance=None,
            correct_pattern=None,
            details={"row_count": 0, "warnings": []},
        )

    # Track warnings (non-fatal issues)
    warnings: list[dict[str, Any]] = []

    # Validate each row
    for row_idx, row in enumerate(result_set):
        for column, value in row.items():
            # Skip NULL values
            if value is None:
                continue

            # Convert to string for validation
            value_str = str(value)

            # Validate ASCII characters
            for char in value_str:
                char_code = ord(char)
                if char_code not in SAFE_ASCII_CHARS:
                    raise NonASCIIOutputError(column, row_idx, char_code)

            # Check for suspicious PHI patterns (warnings only)
            # Only check string values, not numeric values (to avoid false positives)
            if isinstance(value, str):
                phi_pattern = _check_phi_patterns(value_str)
                if phi_pattern:
                    warnings.append(
                        {
                            "row": row_idx,
                            "column": column,
                            "pattern": phi_pattern,
                            "value": value_str[:50],  # Truncate for safety
                        }
                    )

        # Check patient count threshold
        if "Count_Patients" in row:
            patient_count = row["Count_Patients"]
            if isinstance(patient_count, (int, float)) and patient_count < min_patient_count:
                raise PatientCountBelowThresholdError(int(patient_count), min_patient_count)

    # All validations passed
    return ValidationResult(
        success=True,
        request_id=request_id,
        layer="ascii_output",
        code=None,
        message="ASCII output validation passed",
        educational_guidance=None,
        correct_pattern=None,
        details={
            "row_count": row_count,
            "column_count": len(result_set[0]) if result_set else 0,
            "warnings": warnings,
        },
    )


def _check_phi_patterns(value: str) -> str:
    """Check for patterns that resemble PHI (heuristic, returns pattern type or empty string).

    This is a heuristic check that looks for common PHI patterns in output.
    It generates warnings (not errors) for review, as Layer 2 should have
    already blocked PHI columns.

    Args:
        value: String value to check

    Returns:
        Pattern type if suspicious pattern found, empty string otherwise

    Patterns checked:
        - Date patterns (potential DOB)
        - Email addresses
        - Phone numbers
        - SSN-like patterns
        - ZIP codes
    """
    # SSN pattern (XXX-XX-XXXX) - check first since it's more specific than phone
    if re.match(r"^\d{3}-\d{2}-\d{4}$", value):
        return "ssn_pattern"

    # Phone pattern (XXX-XXX-XXXX or similar)
    if re.match(r"^\d{3}-\d{3}-\d{4}$", value):
        return "phone_pattern"

    # Date pattern (YYYY-MM-DD or similar)
    if re.match(r"^\d{4}-\d{2}-\d{2}", value):
        return "date_pattern"

    # Email pattern
    if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
        return "email_pattern"

    # ZIP code (5 or 9 digits) - must be standalone, not part of larger number
    if re.match(r"^\d{5}(-\d{4})?$", value):
        return "zip_pattern"

    return ""


def get_safe_preview(result_set: list[dict[str, Any]], max_rows: int = 5) -> str:
    """Get a safe preview of result set for logging/debugging.

    Args:
        result_set: Result set to preview
        max_rows: Maximum number of rows to include

    Returns:
        String representation of result preview
    """
    if not result_set:
        return "Empty result set"

    preview_rows = result_set[:max_rows]
    lines = [f"Result set preview ({len(result_set)} total rows):"]

    # Add column headers
    if preview_rows:
        columns = list(preview_rows[0].keys())
        lines.append(f"Columns: {', '.join(columns)}")

    # Add sample rows
    for idx, row in enumerate(preview_rows):
        row_str = ", ".join(f"{k}={v}" for k, v in row.items())
        lines.append(f"  Row {idx}: {row_str[:100]}")  # Truncate long rows

    if len(result_set) > max_rows:
        lines.append(f"  ... and {len(result_set) - max_rows} more rows")

    return "\n".join(lines)
