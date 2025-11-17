"""Container execution entrypoint.

This module serves as the entrypoint for containerized query validation.
It handles credential decryption, query validation, and secure cleanup.
"""

import os
import sys
import json
from typing import Dict, Any
from cryptography.fernet import Fernet

from src.validators.ascii_input import validate_ascii_input
from src.validators.phi import validate_phi
from src.validators.aggregation import validate_aggregation
from src.enforcer import validate_no_circumvention, wrap_query
from src.container.cleanup import secure_cleanup


def validate_query(query: str, query_id: str) -> Dict[str, Any]:
    """
    Execute complete validation pipeline.

    Args:
        query: SQL query to validate
        query_id: Unique identifier for this query

    Returns:
        Validation result dictionary with status and details
    """
    try:
        # Layer 0: ASCII validation
        result_0 = validate_ascii_input(query, query_id)
        if not result_0.success:
            return {
                "status": "invalid",
                "layer": "ascii_input",
                "error": str(result_0.error),
                "query_id": query_id,
            }

        # Layer 2: PHI validation
        result_2 = validate_phi(query, query_id)
        if not result_2.success:
            return {
                "status": "invalid",
                "layer": "phi",
                "error": str(result_2.error),
                "query_id": query_id,
            }

        # Layer 3: Aggregation validation
        result_3 = validate_aggregation(query, query_id)
        if not result_3.success:
            return {
                "status": "invalid",
                "layer": "aggregation",
                "error": str(result_3.error),
                "query_id": query_id,
            }

        # Layer 4: Enforcement validation
        result_4 = validate_no_circumvention(query, query_id)
        if not result_4.success:
            return {
                "status": "invalid",
                "layer": "enforcement",
                "error": str(result_4.error),
                "query_id": query_id,
            }

        # Wrap query with enforcement
        wrapped_query = wrap_query(query)

        return {
            "status": "valid",
            "query_id": query_id,
            "wrapped_query": wrapped_query,
            "message": "Query passed all validation layers",
        }

    except Exception as e:
        return {
            "status": "error",
            "query_id": query_id,
            "error": str(e),
            "error_type": type(e).__name__,
        }


def decrypt_credentials(encrypted_hex: str, key: str) -> Dict[str, str]:
    """
    Decrypt database credentials.

    Args:
        encrypted_hex: Hex-encoded encrypted credentials
        key: Fernet encryption key

    Returns:
        Decrypted credentials dictionary
    """
    f = Fernet(key.encode())
    encrypted = bytes.fromhex(encrypted_hex)
    decrypted = f.decrypt(encrypted)
    return json.loads(decrypted)


def main():
    """Main container execution function."""
    try:
        # Read inputs from environment
        encrypted_creds = os.getenv("ENCRYPTED_CREDS")
        query = os.getenv("QUERY")
        query_id = os.getenv("QUERY_ID", "unknown")
        encryption_key = os.getenv("ENCRYPTION_KEY")

        # Validate required inputs
        if not query:
            print(
                json.dumps(
                    {"status": "error", "message": "Missing required QUERY environment variable"}
                )
            )
            sys.exit(1)

        # Only decrypt credentials if provided (not required for validation-only mode)
        credentials = None
        if encrypted_creds and encryption_key:
            credentials = decrypt_credentials(encrypted_creds, encryption_key)

        # Validate query
        result = validate_query(query, query_id)

        # Output result as JSON
        print(json.dumps(result))

        # Secure cleanup
        sensitive_vars = [encrypted_creds, encryption_key]
        if credentials:
            sensitive_vars.append(json.dumps(credentials))
        secure_cleanup(sensitive_vars)

        # Exit with appropriate code
        sys.exit(0 if result["status"] in ["valid", "invalid"] else 1)

    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e), "error_type": type(e).__name__}))
        sys.exit(1)


if __name__ == "__main__":
    main()
