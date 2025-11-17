"""Schema loading and caching for OMOP CDM validation.

This module provides a singleton cache for OMOP schema definitions, enabling
fast validation of table and column references against the configured schema.
"""

from pathlib import Path
from typing import Dict, Set

import yaml  # type: ignore[import-untyped]


class SchemaCache:
    """Singleton cache for OMOP schema definitions.

    Loads and caches the OMOP CDM schema from YAML configuration on first access.
    Provides O(1) lookups for table and column validation.

    Attributes:
        _schema_data: Dictionary mapping table names to sets of column names
    """

    _instance: "SchemaCache | None" = None
    _schema_data: Dict[str, Set[str]] = {}
    _loaded: bool = False

    def __new__(cls) -> "SchemaCache":
        """Create or return singleton instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize schema cache (loads schema on first instantiation)."""
        if not self._loaded:
            self._load_schema()
            self.__class__._loaded = True

    def _load_schema(self) -> None:
        """Load OMOP schema from YAML configuration.

        Raises:
            FileNotFoundError: If schema file not found
            yaml.YAMLError: If schema file is malformed
        """
        schema_path = Path(__file__).parent.parent.parent / "config" / "schemas" / "omop_5.4.yaml"

        if not schema_path.exists():
            raise FileNotFoundError(f"Schema configuration not found: {schema_path}")

        with open(schema_path, "r") as f:
            schema = yaml.safe_load(f)

        # Build lookup structures: table_name -> set(column_names)
        tables = schema.get("tables", {})
        for table_name, table_def in tables.items():
            columns = table_def.get("columns", [])
            # Convert to set of lowercase strings for case-insensitive matching
            self._schema_data[table_name.lower()] = {str(col).lower() for col in columns}

    def is_valid_table(self, table_name: str) -> bool:
        """Check if table exists in schema.

        Args:
            table_name: Table name to validate (case-insensitive)

        Returns:
            True if table exists, False otherwise
        """
        return table_name.lower() in self._schema_data

    def is_valid_column(self, table_name: str, column_name: str) -> bool:
        """Check if column exists in table.

        Args:
            table_name: Table name (case-insensitive)
            column_name: Column name to validate (case-insensitive)

        Returns:
            True if column exists in table, False otherwise
        """
        table_lower = table_name.lower()
        if table_lower not in self._schema_data:
            return False
        return column_name.lower() in self._schema_data[table_lower]

    def get_valid_tables(self) -> Set[str]:
        """Get set of all valid table names.

        Returns:
            Set of table names (lowercase)
        """
        return set(self._schema_data.keys())

    def get_valid_columns(self, table_name: str) -> Set[str]:
        """Get set of valid columns for a table.

        Args:
            table_name: Table name (case-insensitive)

        Returns:
            Set of column names (lowercase), or empty set if table not found
        """
        return self._schema_data.get(table_name.lower(), set())


# Global singleton instance
schema_cache = SchemaCache()
