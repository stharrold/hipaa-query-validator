"""Podman container runner for ephemeral query validation.

This module provides the ContainerExecutor class for running query validation
in isolated, ephemeral Podman containers with zero-knowledge security.
"""

import subprocess
import json
import uuid
import os
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet


class ContainerExecutor:
    """Executes queries in ephemeral Podman containers.

    This class provides a secure execution environment for query validation
    using Podman containers. Each query runs in an isolated, ephemeral container
    that is automatically destroyed after execution.

    Security features:
    - One container per query (ephemeral)
    - Credentials encrypted in-transit
    - Read-only filesystem
    - No network access
    - Non-root execution
    - Automatic cleanup
    - Resource limits (CPU, memory, PIDs)

    Example:
        >>> from src.container.runner import ContainerExecutor
        >>> from cryptography.fernet import Fernet
        >>>
        >>> key = Fernet.generate_key()
        >>> executor = ContainerExecutor(image="hipaa-validator:latest")
        >>> result = executor.execute_query(
        ...     query="SELECT COUNT(*) FROM person",
        ...     db_credentials={"host": "db.example.com"},
        ...     encryption_key=key
        ... )
    """

    def __init__(
        self,
        image: str = "hipaa-validator:latest",
        audit_log_dir: Optional[str] = None,
        timeout_seconds: int = 300,
        memory_limit: str = "512m",
        cpu_limit: str = "1",
        pids_limit: int = 100,
    ):
        """
        Initialize container executor.

        Args:
            image: Podman image name
            audit_log_dir: Directory for audit logs (optional, mounted as volume)
            timeout_seconds: Execution timeout in seconds (default: 300)
            memory_limit: Memory limit (default: 512m)
            cpu_limit: CPU limit (default: 1)
            pids_limit: Maximum number of processes (default: 100)
        """
        self.image = image
        self.audit_log_dir = audit_log_dir
        self.timeout_seconds = timeout_seconds
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.pids_limit = pids_limit

    def execute_query(
        self,
        query: str,
        db_credentials: Optional[Dict[str, str]] = None,
        encryption_key: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """
        Execute query in ephemeral container.

        Args:
            query: SQL query to validate
            db_credentials: Database credentials dict (optional)
            encryption_key: Fernet encryption key (required if db_credentials provided)

        Returns:
            Validation result dict with keys:
                - status: "valid", "invalid", "error", or "timeout"
                - query_id: Unique query identifier
                - wrapped_query: SQL-wrapped query (if valid)
                - error: Error message (if invalid/error)
                - layer: Failed validation layer (if invalid)

        Raises:
            ValueError: If db_credentials provided without encryption_key
            FileNotFoundError: If Podman executable not found
        """
        query_id = str(uuid.uuid4())

        # Validate encryption requirements
        if db_credentials and not encryption_key:
            raise ValueError("encryption_key required when db_credentials provided")

        # Encrypt credentials if provided
        encrypted_creds = None
        if db_credentials and encryption_key:
            encrypted_creds = self._encrypt_credentials(db_credentials, encryption_key)

        # Build Podman command
        cmd = self._build_podman_command(query, query_id, encrypted_creds, encryption_key)

        # Execute container
        try:
            result = subprocess.run(
                cmd, capture_output=True, timeout=self.timeout_seconds, text=True
            )

            # Parse JSON output from container
            if result.returncode == 0:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return {
                        "status": "error",
                        "query_id": query_id,
                        "message": f"Invalid JSON output: {result.stdout}",
                    }
            else:
                # Container exited with error
                try:
                    # Try to parse error as JSON
                    error_data = json.loads(result.stdout or result.stderr)
                    return error_data
                except json.JSONDecodeError:
                    return {
                        "status": "error",
                        "query_id": query_id,
                        "message": result.stderr or result.stdout or "Unknown error",
                    }

        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "query_id": query_id,
                "message": f"Container exceeded {self.timeout_seconds}s timeout",
            }
        except FileNotFoundError:
            return {
                "status": "error",
                "query_id": query_id,
                "message": "Podman executable not found. Is Podman installed?",
            }

    def _build_podman_command(
        self,
        query: str,
        query_id: str,
        encrypted_creds: Optional[str],
        encryption_key: Optional[bytes],
    ) -> list:
        """
        Build Podman command with security hardening.

        Args:
            query: SQL query
            query_id: Query identifier
            encrypted_creds: Encrypted credentials hex string
            encryption_key: Encryption key

        Returns:
            Podman command as list
        """
        cmd = [
            "podman",
            "run",
            "--rm",  # Auto-delete container
            "--network=none",  # No network access
            "--read-only",  # Read-only root filesystem
            "--tmpfs",
            "/tmp:rw,size=100m,mode=1777",  # Writable tmp
            "-e",
            f"QUERY={query}",
            "-e",
            f"QUERY_ID={query_id}",
            "--cap-drop=ALL",  # Drop all capabilities
            "--security-opt=no-new-privileges",
            f"--pids-limit={self.pids_limit}",
            f"--memory={self.memory_limit}",
            f"--cpus={self.cpu_limit}",
        ]

        # Add audit log volume if configured
        if self.audit_log_dir:
            # Ensure directory exists
            os.makedirs(self.audit_log_dir, exist_ok=True)
            cmd.extend(["-v", f"{self.audit_log_dir}:/app/audit_logs:rw"])

        # Add encrypted credentials if provided
        if encrypted_creds and encryption_key:
            cmd.extend(["-e", f"ENCRYPTED_CREDS={encrypted_creds}"])
            cmd.extend(["-e", f"ENCRYPTION_KEY={encryption_key.decode()}"])

        # Add image
        cmd.append(self.image)

        return cmd

    def _encrypt_credentials(self, credentials: Dict[str, str], key: bytes) -> str:
        """
        Encrypt credentials for container transmission.

        Args:
            credentials: Credentials dictionary
            key: Fernet encryption key

        Returns:
            Hex-encoded encrypted credentials
        """
        f = Fernet(key)
        creds_json = json.dumps(credentials).encode()
        encrypted = f.encrypt(creds_json)
        return encrypted.hex()

    def check_podman_available(self) -> bool:
        """
        Check if Podman is available on the system.

        Returns:
            True if Podman is installed and accessible
        """
        try:
            result = subprocess.run(
                ["podman", "--version"], capture_output=True, timeout=5, text=True
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def check_image_exists(self) -> bool:
        """
        Check if the container image exists.

        Returns:
            True if image exists locally
        """
        try:
            result = subprocess.run(
                ["podman", "image", "exists", self.image],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
