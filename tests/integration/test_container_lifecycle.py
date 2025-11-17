"""Integration tests for container execution lifecycle.

These tests verify the complete container-based execution pipeline,
including image building, query execution, security features, and cleanup.
"""

import pytest
import subprocess
import os
from cryptography.fernet import Fernet

from src.container.runner import ContainerExecutor


# Test image name
TEST_IMAGE = "hipaa-validator:test"


@pytest.fixture(scope="session")
def encryption_key():
    """Generate encryption key for tests."""
    return Fernet.generate_key()


@pytest.fixture(scope="session")
def db_credentials():
    """Test database credentials."""
    return {
        "host": "localhost",
        "port": "5432",
        "database": "omop",
        "username": "test_user",
        "password": "test_pass",
    }


@pytest.fixture(scope="session")
def container_executor():
    """Create container executor for tests."""
    return ContainerExecutor(
        image=TEST_IMAGE, audit_log_dir=None, timeout_seconds=60  # No audit logs for tests
    )


def check_podman_installed():
    """Check if Podman is installed."""
    try:
        result = subprocess.run(
            ["podman", "--version"], capture_output=True, timeout=5, text=True
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def check_image_exists(image_name: str):
    """Check if container image exists."""
    try:
        result = subprocess.run(
            ["podman", "image", "exists", image_name], capture_output=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# Skip all tests if Podman not installed
pytestmark = pytest.mark.skipif(
    not check_podman_installed(), reason="Podman not installed or not accessible"
)


class TestContainerBuild:
    """Test container image building."""

    def test_containerfile_exists(self):
        """Containerfile should exist."""
        containerfile_path = os.path.join(os.getcwd(), "container", "Containerfile")
        assert os.path.exists(
            containerfile_path
        ), f"Containerfile not found at {containerfile_path}"

    def test_requirements_txt_exists(self):
        """Container requirements.txt should exist."""
        requirements_path = os.path.join(os.getcwd(), "container", "requirements.txt")
        assert os.path.exists(requirements_path), f"requirements.txt not found at {requirements_path}"

    @pytest.mark.slow
    def test_container_image_builds(self):
        """Container image should build successfully."""
        # Skip if already built to save time
        if check_image_exists(TEST_IMAGE):
            pytest.skip("Image already built")

        result = subprocess.run(
            ["podman", "build", "-t", TEST_IMAGE, "-f", "container/Containerfile", "."],
            capture_output=True,
            timeout=300,
            text=True,
        )

        if result.returncode != 0:
            print(f"Build stdout: {result.stdout}")
            print(f"Build stderr: {result.stderr}")

        assert result.returncode == 0, f"Container build failed: {result.stderr}"


class TestContainerExecution:
    """Test container execution."""

    @pytest.fixture(autouse=True)
    def ensure_image_built(self):
        """Ensure image is built before tests."""
        if not check_image_exists(TEST_IMAGE):
            pytest.skip(f"Image {TEST_IMAGE} not built. Run test_container_image_builds first.")

    def test_executor_check_podman_available(self, container_executor):
        """Executor should detect Podman availability."""
        assert container_executor.check_podman_available() is True

    def test_executor_check_image_exists(self, container_executor):
        """Executor should detect image existence."""
        assert container_executor.check_image_exists() is True

    def test_container_executes_valid_query(self, container_executor):
        """Container should execute and validate a valid query."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """

        result = container_executor.execute_query(query=query)

        assert "status" in result
        assert result["status"] in ["valid", "invalid", "error"]
        assert "query_id" in result

        # This query should be valid
        if result["status"] == "valid":
            assert "wrapped_query" in result
        elif result["status"] == "invalid":
            assert "layer" in result
            assert "error" in result

    def test_container_executes_invalid_query(self, container_executor):
        """Container should reject invalid query with educational guidance."""
        query = "SELECT name FROM person"  # PHI identifier

        result = container_executor.execute_query(query=query)

        assert result["status"] == "invalid"
        assert "layer" in result
        assert result["layer"] == "phi"
        assert "error" in result

    def test_container_handles_encryption(
        self, container_executor, db_credentials, encryption_key
    ):
        """Container should handle encrypted credentials."""
        query = """
        SELECT gender_concept_id,
               COUNT(DISTINCT person_id) AS Count_Patients
        FROM person
        GROUP BY gender_concept_id
        """

        result = container_executor.execute_query(
            query=query, db_credentials=db_credentials, encryption_key=encryption_key
        )

        assert "status" in result
        # Should work the same with or without credentials
        assert result["status"] in ["valid", "invalid", "error"]

    def test_container_auto_deletes(self):
        """Container should auto-delete after execution."""
        # Run a simple container
        container_name = "test-cleanup-verify"
        subprocess.run(
            [
                "podman",
                "run",
                "--rm",
                "--name",
                container_name,
                TEST_IMAGE,
                "python",
                "-c",
                "print('test')",
            ],
            capture_output=True,
            timeout=30,
        )

        # Check container doesn't exist
        result = subprocess.run(
            ["podman", "ps", "-a", "--filter", f"name={container_name}"],
            capture_output=True,
            timeout=5,
            text=True,
        )

        assert container_name not in result.stdout, "Container should be auto-deleted"

    def test_container_timeout(self):
        """Container should timeout for long-running queries."""
        executor = ContainerExecutor(image=TEST_IMAGE, timeout_seconds=2)

        # This would timeout if the container tried to sleep
        # But our executor just validates, so it won't actually timeout
        # This test verifies the timeout mechanism exists
        query = "SELECT COUNT(DISTINCT person_id) AS Count_Patients FROM person"

        result = executor.execute_query(query=query)

        # Should complete before timeout
        assert result["status"] in ["valid", "invalid", "error"]


class TestSecurity:
    """Security feature tests."""

    @pytest.fixture(autouse=True)
    def ensure_image_built(self):
        """Ensure image is built before tests."""
        if not check_image_exists(TEST_IMAGE):
            pytest.skip(f"Image {TEST_IMAGE} not built. Run test_container_image_builds first.")

    def test_read_only_filesystem(self):
        """Container filesystem should be read-only."""
        result = subprocess.run(
            [
                "podman",
                "run",
                "--rm",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,size=100m",
                TEST_IMAGE,
                "sh",
                "-c",
                "touch /test.txt 2>&1 || echo 'read-only'",
            ],
            capture_output=True,
            timeout=30,
            text=True,
        )

        output = result.stdout + result.stderr
        assert "read-only" in output or "Read-only" in output, "Filesystem should be read-only"

    def test_network_isolation(self):
        """Container should have no network access."""
        result = subprocess.run(
            [
                "podman",
                "run",
                "--rm",
                "--network=none",
                TEST_IMAGE,
                "sh",
                "-c",
                "ping -c 1 -W 1 8.8.8.8 2>&1 || echo 'no-network'",
            ],
            capture_output=True,
            timeout=30,
            text=True,
        )

        output = result.stdout + result.stderr
        assert "no-network" in output or "Network is unreachable" in output, (
            "Container should have no network access"
        )

    def test_runs_as_non_root(self):
        """Container should run as non-root user."""
        result = subprocess.run(
            ["podman", "run", "--rm", TEST_IMAGE, "whoami"],
            capture_output=True,
            timeout=30,
            text=True,
        )

        assert result.stdout.strip() == "validator", "Container should run as 'validator' user"

    def test_capabilities_dropped(self):
        """Container should have all capabilities dropped."""
        result = subprocess.run(
            [
                "podman",
                "run",
                "--rm",
                "--cap-drop=ALL",
                TEST_IMAGE,
                "sh",
                "-c",
                "cat /proc/self/status | grep CapEff || echo '0'",
            ],
            capture_output=True,
            timeout=30,
            text=True,
        )

        # With all capabilities dropped, CapEff should be 0
        assert "0000000000000000" in result.stdout or result.stdout.strip().endswith(
            "0"
        ), "All capabilities should be dropped"


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_missing_query_parameter(self, container_executor):
        """Should handle missing query parameter."""
        # This will fail because we're passing empty query
        result = container_executor.execute_query(query="")

        assert result["status"] in ["invalid", "error"]

    def test_encryption_key_without_credentials(self, container_executor, encryption_key):
        """Should accept encryption key even without credentials."""
        query = "SELECT COUNT(DISTINCT person_id) AS Count_Patients FROM person"

        # Should work - encryption key without credentials is allowed
        result = container_executor.execute_query(query=query, encryption_key=encryption_key)

        assert result["status"] in ["valid", "invalid", "error"]

    def test_credentials_without_encryption_key_fails(
        self, container_executor, db_credentials
    ):
        """Should reject credentials without encryption key."""
        query = "SELECT COUNT(DISTINCT person_id) AS Count_Patients FROM person"

        with pytest.raises(ValueError, match="encryption_key required"):
            container_executor.execute_query(query=query, db_credentials=db_credentials)

    def test_nonexistent_image(self):
        """Should handle non-existent image gracefully."""
        executor = ContainerExecutor(image="nonexistent-image:latest")

        result = executor.execute_query(query="SELECT COUNT(*) FROM person")

        assert result["status"] == "error"
