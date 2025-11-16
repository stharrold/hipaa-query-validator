"""Layer 0: ASCII Input Validation.

This module implements Unicode-based SQL injection prevention by ensuring
all input contains only ASCII characters (0x20-0x7E) plus newline, carriage
return, and tab.

Performance target: <5ms for typical queries
Security: Prevents Unicode normalization attacks, homograph attacks, and
          zero-width character injection
"""

from typing import Optional

from ..errors import (
    EmptyQueryError,
    InvalidControlCharacterError,
    NonASCIICharacterError,
)
from ..models import ValidationResult


# Allowed ASCII characters:
# - Printable ASCII: 0x20 (space) to 0x7E (~)
# - Whitespace control characters: \n (0x0A), \r (0x0D), \t (0x09)
ALLOWED_PRINTABLE_MIN = 0x20
ALLOWED_PRINTABLE_MAX = 0x7E
ALLOWED_CONTROL_CHARS = {0x09, 0x0A, 0x0D}  # \t, \n, \r


def validate_ascii_input(query: str, request_id: str) -> ValidationResult:
    """Validate that query contains only allowed ASCII characters.

    This is Layer 0 of the validation pipeline and must be the first
    validation performed to prevent Unicode-based attacks.

    Args:
        query: SQL query string to validate
        request_id: Unique identifier for this validation request

    Returns:
        ValidationResult indicating success or failure

    Raises:
        EmptyQueryError: If query is empty or whitespace-only
        NonASCIICharacterError: If non-ASCII character detected
        InvalidControlCharacterError: If invalid control character detected

    Performance:
        - Best case: O(n) where n is query length
        - Target: <5ms for queries up to 10KB
        - Implementation: Single-pass character validation

    Security:
        Prevents:
        - Unicode normalization attacks (e.g., U+FE64 vs U+003C)
        - Homograph attacks (e.g., Cyrillic 'а' vs Latin 'a')
        - Zero-width character injection
        - Right-to-left override attacks
        - Combining character manipulation
    """
    # Check for empty query
    if not query or not query.strip():
        raise EmptyQueryError()

    # Single-pass validation of all characters
    for position, char in enumerate(query):
        code_point = ord(char)

        # Check if it's a printable ASCII character
        if ALLOWED_PRINTABLE_MIN <= code_point <= ALLOWED_PRINTABLE_MAX:
            continue

        # Check if it's an allowed control character
        if code_point in ALLOWED_CONTROL_CHARS:
            continue

        # If we get here, character is not allowed
        if code_point > 0x7E:
            # Non-ASCII character (Unicode)
            raise NonASCIICharacterError(position, char, code_point)
        else:
            # ASCII but invalid control character
            raise InvalidControlCharacterError(position, code_point)

    # All characters are valid ASCII
    return ValidationResult(
        success=True,
        request_id=request_id,
        layer="ascii_input",
        code=None,
        message="ASCII input validation passed",
        educational_guidance=None,
        correct_pattern=None,
    )


def is_ascii_printable(char: str) -> bool:
    """Check if a character is printable ASCII (0x20-0x7E).

    Args:
        char: Single character to check

    Returns:
        True if character is printable ASCII, False otherwise

    Examples:
        >>> is_ascii_printable('A')
        True
        >>> is_ascii_printable(' ')
        True
        >>> is_ascii_printable('\\n')
        False
        >>> is_ascii_printable('é')
        False
    """
    if len(char) != 1:
        raise ValueError("Input must be a single character")
    code_point = ord(char)
    return ALLOWED_PRINTABLE_MIN <= code_point <= ALLOWED_PRINTABLE_MAX


def is_allowed_control_char(char: str) -> bool:
    """Check if a character is an allowed control character (\\n, \\r, \\t).

    Args:
        char: Single character to check

    Returns:
        True if character is an allowed control character, False otherwise

    Examples:
        >>> is_allowed_control_char('\\n')
        True
        >>> is_allowed_control_char('\\t')
        True
        >>> is_allowed_control_char('\\x00')
        False
    """
    if len(char) != 1:
        raise ValueError("Input must be a single character")
    return ord(char) in ALLOWED_CONTROL_CHARS


def get_non_ascii_positions(query: str) -> list[tuple[int, str, int]]:
    """Get all positions of non-ASCII characters in query.

    Useful for debugging and detailed error reporting.

    Args:
        query: Query string to analyze

    Returns:
        List of tuples: (position, character, code_point)

    Examples:
        >>> get_non_ascii_positions("SELECT 'hello'")
        []
        >>> get_non_ascii_positions("SELECT 'café'")
        [(13, 'é', 233)]
    """
    non_ascii_chars = []

    for position, char in enumerate(query):
        code_point = ord(char)

        # Skip valid printable ASCII
        if ALLOWED_PRINTABLE_MIN <= code_point <= ALLOWED_PRINTABLE_MAX:
            continue

        # Skip allowed control characters
        if code_point in ALLOWED_CONTROL_CHARS:
            continue

        # This character is not allowed
        non_ascii_chars.append((position, char, code_point))

    return non_ascii_chars


def sanitize_for_logging(query: str, max_length: int = 200) -> str:
    """Sanitize query for safe logging (remove non-ASCII, truncate).

    Args:
        query: Query string to sanitize
        max_length: Maximum length of sanitized output

    Returns:
        Sanitized query string safe for logging

    Examples:
        >>> sanitize_for_logging("SELECT * FROM person")
        'SELECT * FROM person'
        >>> sanitize_for_logging("SELECT 'café'")
        "SELECT 'caf[U+00E9]'"
    """
    result = []

    for char in query:
        code_point = ord(char)

        # Keep valid printable ASCII
        if ALLOWED_PRINTABLE_MIN <= code_point <= ALLOWED_PRINTABLE_MAX:
            result.append(char)
        # Keep allowed control characters (but represent them)
        elif code_point == 0x09:  # \t
            result.append("\\t")
        elif code_point == 0x0A:  # \n
            result.append("\\n")
        elif code_point == 0x0D:  # \r
            result.append("\\r")
        # Replace other characters with Unicode notation
        else:
            result.append(f"[U+{code_point:04X}]")

    sanitized = "".join(result)

    # Truncate if too long
    if len(sanitized) > max_length:
        sanitized = sanitized[: max_length - 3] + "..."

    return sanitized
