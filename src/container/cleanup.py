"""Secure memory cleanup procedures.

This module provides functions for securely clearing sensitive data from memory,
including credentials, encryption keys, and query content.
"""

import gc
import ctypes
import os
from typing import List, Any, Optional


def secure_cleanup(sensitive_vars: List[Optional[Any]]) -> None:
    """
    Securely clear sensitive data from memory.

    This function attempts to overwrite memory locations containing sensitive
    data before allowing garbage collection. Note that Python's memory management
    makes true secure deletion difficult, but this provides best-effort clearing.

    Args:
        sensitive_vars: List of sensitive variables to clear (strings, bytes, etc.)
    """
    # Overwrite each variable
    for var in sensitive_vars:
        if var is None:
            continue

        if isinstance(var, (str, bytes)):
            try:
                # Convert strings to bytes
                if isinstance(var, str):
                    var_bytes = var.encode()
                else:
                    var_bytes = var

                # Attempt to overwrite memory
                # Note: This is best-effort in Python due to string immutability
                # and memory management. For true secure deletion, use C extensions.
                try:
                    ctypes.memset(id(var_bytes), 0, len(var_bytes))
                except (ValueError, OSError):
                    # memset may fail for various reasons in Python
                    # Continue with best effort
                    pass

            except Exception:
                # Best effort - continue even if individual cleanup fails
                pass

    # Force garbage collection
    gc.collect()

    # Clear sensitive environment variables
    sensitive_env_vars = ["ENCRYPTED_CREDS", "QUERY", "ENCRYPTION_KEY", "DB_PASSWORD"]
    for key in list(os.environ.keys()):
        if key in sensitive_env_vars or "PASSWORD" in key or "SECRET" in key or "KEY" in key:
            try:
                del os.environ[key]
            except KeyError:
                pass


def clear_all_environment() -> None:
    """
    Clear all environment variables.

    WARNING: This clears ALL environment variables, which may break
    system functionality. Only use in isolated container environments.
    """
    for key in list(os.environ.keys()):
        try:
            del os.environ[key]
        except KeyError:
            pass
