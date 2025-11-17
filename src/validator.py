"""Unified HIPAA query validator with comprehensive audit logging.

This module provides the main entry point for query validation, orchestrating
all validation layers and providing comprehensive audit logging for HIPAA
compliance (45 CFR § 164.312(b) and 164.530(j)).

The validation pipeline executes layers sequentially with fast-fail behavior:
1. Layer 0: ASCII Input Validation
2. Layer 2: PHI Column Validation
3. Layer 3: Aggregation Enforcement
4. Layer 4: SQL Enforcement (anti-circumvention)

All validation events, errors, and security detections are logged to
tamper-evident JSONL audit logs with 6-year retention.
"""

import time
import uuid

from src.audit.events import (
    create_error_event,
    create_security_event,
    create_validation_event,
    hash_query,
)
from src.audit.logger import log_event
from src.enforcer import validate_no_circumvention, wrap_query
from src.errors import (
    CTENotAllowedError,
    SubqueryNotAllowedError,
    ValidationError,
)
from src.validators.aggregation import validate_aggregation
from src.validators.ascii_input import validate_ascii_input
from src.validators.phi import validate_phi


def generate_request_id() -> str:
    """Generate unique request ID for validation.

    Returns:
        UUID-based request ID
    """
    return f"req-{uuid.uuid4().hex[:12]}"


def _get_layer_from_error(error: ValidationError) -> int:
    """Extract layer number from error code.

    Args:
        error: ValidationError instance

    Returns:
        Layer number (0-8) or -1 if unknown
    """
    code = error.code
    if code.startswith("E0"):
        return 0
    elif code.startswith("E1"):
        return 1
    elif code.startswith("E2"):
        return 2
    elif code.startswith("E3"):
        return 3
    elif code.startswith("E4"):
        return 4
    elif code.startswith("E5"):
        return 5
    elif code.startswith("E6"):
        return 6
    elif code.startswith("E7"):
        return 7
    elif code.startswith("E8"):
        return 8
    return -1


def _is_security_event(error: ValidationError) -> bool:
    """Determine if error represents a security event.

    Security events include SQL injection attempts and circumvention attempts.

    Args:
        error: ValidationError instance

    Returns:
        True if this is a security-related error
    """
    return isinstance(error, (SubqueryNotAllowedError, CTENotAllowedError))


def validate_query(
    query: str,
    request_id: str | None = None,
    user_id: str = "unknown",
    session_id: str = "unknown",
    ip_address: str = "",
    container_id: str = "",
    enable_audit: bool = True,
) -> dict:
    """Validate SQL query through all security layers with audit logging.

    This is the main entry point for query validation. It executes all
    validation layers sequentially and logs comprehensive audit events.

    Args:
        query: SQL query string to validate
        request_id: Optional request ID (auto-generated if not provided)
        user_id: User identifier for audit trail
        session_id: Session identifier for audit trail
        ip_address: Source IP address for audit trail
        container_id: Container/execution environment ID
        enable_audit: Whether to enable audit logging (default True)

    Returns:
        Dictionary with validation result:
        {
            "status": "valid" | "invalid",
            "request_id": str,
            "query_hash": str,
            "validation_time_ms": float,
            "layer_times_ms": dict,
            "layers_passed": list,
            "layers_failed": list,
            "error_code": str (if invalid),
            "error_message": str (if invalid),
            "wrapped_query": str (if valid)
        }

    Example:
        >>> result = validate_query("SELECT COUNT(DISTINCT person_id) AS Count_Patients FROM person")
        >>> assert result["status"] == "valid"
        >>> print(result["wrapped_query"])
    """
    # Generate request ID if not provided
    if request_id is None:
        request_id = generate_request_id()

    # Hash query for audit logging (NEVER log full query)
    query_hash = hash_query(query)

    # Track timing and results
    start_time = time.perf_counter()
    layer_times: dict[str, float] = {}
    layers_passed: list[int] = []
    layers_failed: list[int] = []

    try:
        # Layer 0: ASCII Input Validation
        layer_start = time.perf_counter()
        validate_ascii_input(query, request_id)
        layer_times["layer_0_ascii"] = (time.perf_counter() - layer_start) * 1000
        layers_passed.append(0)

        # Layer 2: PHI Column Validation
        layer_start = time.perf_counter()
        validate_phi(query, request_id)
        layer_times["layer_2_phi"] = (time.perf_counter() - layer_start) * 1000
        layers_passed.append(2)

        # Layer 3: Aggregation Enforcement
        layer_start = time.perf_counter()
        validate_aggregation(query, request_id)
        layer_times["layer_3_aggregation"] = (time.perf_counter() - layer_start) * 1000
        layers_passed.append(3)

        # Layer 4: SQL Enforcement (anti-circumvention)
        layer_start = time.perf_counter()
        validate_no_circumvention(query, request_id)
        layer_times["layer_4_enforcement"] = (time.perf_counter() - layer_start) * 1000
        layers_passed.append(4)

        # All layers passed - wrap query with enforcement
        wrapped_query = wrap_query(query)

        # Calculate total validation time
        total_time_ms = (time.perf_counter() - start_time) * 1000

        # Log successful validation
        if enable_audit:
            event = create_validation_event(
                query_hash=query_hash,
                layers_passed=layers_passed,
                layers_failed=layers_failed,
                total_time_ms=total_time_ms,
                layer_times=layer_times,
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                container_id=container_id,
            )
            log_event(event)

        return {
            "status": "valid",
            "request_id": request_id,
            "query_hash": query_hash,
            "validation_time_ms": round(total_time_ms, 2),
            "layer_times_ms": {k: round(v, 2) for k, v in layer_times.items()},
            "layers_passed": layers_passed,
            "layers_failed": layers_failed,
            "wrapped_query": wrapped_query,
        }

    except ValidationError as e:
        # Determine which layer failed
        layer = _get_layer_from_error(e)
        layers_failed.append(layer)

        # Calculate total validation time
        total_time_ms = (time.perf_counter() - start_time) * 1000

        # Log validation failure
        if enable_audit:
            # Log validation event (with failure)
            validation_event = create_validation_event(
                query_hash=query_hash,
                layers_passed=layers_passed,
                layers_failed=layers_failed,
                total_time_ms=total_time_ms,
                layer_times=layer_times,
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                container_id=container_id,
            )
            log_event(validation_event)

            # Log error event
            error_event = create_error_event(
                query_hash=query_hash,
                error_code=e.code,
                error_type=type(e).__name__,
                layer=layer,
                message=str(e),
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                container_id=container_id,
            )
            log_event(error_event)

            # Log security event if applicable
            if _is_security_event(e):
                security_event = create_security_event(
                    query_hash=query_hash,
                    event_subtype="CIRCUMVENTION_ATTEMPT",
                    detection_layer=layer,
                    pattern=type(e).__name__,
                    blocked=True,
                    user_id=user_id,
                    session_id=session_id,
                    ip_address=ip_address,
                    container_id=container_id,
                )
                log_event(security_event)

        return {
            "status": "invalid",
            "request_id": request_id,
            "query_hash": query_hash,
            "validation_time_ms": round(total_time_ms, 2),
            "layer_times_ms": {k: round(v, 2) for k, v in layer_times.items()},
            "layers_passed": layers_passed,
            "layers_failed": layers_failed,
            "error_code": e.code,
            "error_message": str(e),
            "error_layer": layer,
        }


def validate_query_silent(query: str, request_id: str | None = None) -> bool:
    """Validate query without audit logging (for internal use only).

    WARNING: This function bypasses audit logging and should only be used
    for internal validation checks, not for production query validation.

    Args:
        query: SQL query to validate
        request_id: Optional request ID

    Returns:
        True if query is valid, False otherwise
    """
    result = validate_query(query, request_id=request_id, enable_audit=False)
    status: str = result["status"]
    return status == "valid"
