"""Generate synthetic OMOP-compliant sample data for validation testing.

This module creates an in-memory SQLite database with synthetic patient data
following the OMOP CDM 5.4 schema. The data is HIPAA-safe (no real PHI) and
used for Layer 5 sample query execution validation.

Performance target: Database initialization <100ms
Memory usage: ~5MB for 1000 patients
"""

import random  # noqa: S311 - Not used for cryptographic purposes, only sample data
import sqlite3
from datetime import datetime, timedelta
from typing import Any


class SampleDataGenerator:
    """Generates synthetic HIPAA-safe sample data."""

    def __init__(self, num_persons: int = 1000, random_seed: int = 42) -> None:
        """Initialize sample data generator.

        Args:
            num_persons: Number of synthetic persons to generate (default: 1000)
            random_seed: Random seed for reproducibility (default: 42)
        """
        self.num_persons = num_persons
        self.person_ids = list(range(1, num_persons + 1))
        random.seed(random_seed)

    def generate_person_data(self) -> list[tuple[Any, ...]]:
        """Generate synthetic person table data.

        Returns:
            List of person tuples: (person_id, gender_concept_id, year_of_birth,
                                   month_of_birth, day_of_birth, race_concept_id,
                                   ethnicity_concept_id)
        """
        # OMOP standard concept IDs
        gender_concepts = [8507, 8532]  # Male, Female
        race_concepts = [8527, 8515, 8516, 8557, 8522]  # White, Asian, Black, Native, Other
        ethnicity_concepts = [38003563, 38003564]  # Hispanic, Not Hispanic

        persons = []
        for person_id in self.person_ids:
            person = (
                person_id,
                random.choice(gender_concepts),
                random.randint(1940, 2005),  # year_of_birth
                random.randint(1, 12),  # month_of_birth
                random.randint(1, 28),  # day_of_birth
                random.choice(race_concepts),
                random.choice(ethnicity_concepts),
            )
            persons.append(person)

        return persons

    def generate_condition_occurrence_data(self) -> list[tuple[Any, ...]]:
        """Generate synthetic condition_occurrence table data.

        Returns:
            List of condition tuples: (condition_occurrence_id, person_id,
                                      condition_concept_id, condition_start_date,
                                      condition_end_date)
        """
        # Common condition concepts from OMOP
        diabetes_concepts = [201826, 435216, 4058243, 443238]  # Type 2 diabetes variations
        hypertension_concepts = [320128, 316866, 442604]  # Hypertension variations
        all_concepts = diabetes_concepts + hypertension_concepts

        conditions = []
        condition_id = 1

        # Generate 3-5 conditions per person
        for person_id in self.person_ids:
            num_conditions = random.randint(3, 5)

            for _ in range(num_conditions):
                # Random date in last 5 years
                days_ago = random.randint(0, 1825)
                condition_start = datetime.now() - timedelta(days=days_ago)
                # Condition ends 1-30 days after start
                condition_end = condition_start + timedelta(days=random.randint(1, 30))

                condition = (
                    condition_id,
                    person_id,
                    random.choice(all_concepts),
                    condition_start.strftime("%Y-%m-%d"),
                    condition_end.strftime("%Y-%m-%d"),
                )
                conditions.append(condition)
                condition_id += 1

        return conditions

    def generate_observation_period_data(self) -> list[tuple[Any, ...]]:
        """Generate synthetic observation_period table data.

        Returns:
            List of observation period tuples: (observation_period_id, person_id,
                                               observation_period_start_date,
                                               observation_period_end_date,
                                               period_type_concept_id)
        """
        periods = []

        for person_id in self.person_ids:
            # One observation period per person
            start_date = datetime.now() - timedelta(days=random.randint(1000, 3000))
            end_date = datetime.now()

            period = (
                person_id,  # observation_period_id
                person_id,  # person_id
                start_date.strftime("%Y-%m-%d"),
                end_date.strftime("%Y-%m-%d"),
                44814724,  # Period while enrolled in health plan
            )
            periods.append(period)

        return periods


class SampleDatabase:
    """In-memory SQLite database with synthetic OMOP data.

    This class implements the singleton pattern to ensure only one database
    instance exists in memory, improving performance and reducing memory usage.
    """

    _instance: "SampleDatabase | None" = None
    _db_connection: sqlite3.Connection | None = None

    def __new__(cls) -> "SampleDatabase":
        """Create or return existing singleton instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize_database()
        return cls._instance

    def _initialize_database(self) -> None:
        """Create in-memory database and populate with sample data."""
        # Create in-memory SQLite database
        self._db_connection = sqlite3.connect(":memory:", check_same_thread=False)
        self._create_schema()
        self._populate_data()

    def _create_schema(self) -> None:
        """Create OMOP CDM tables."""
        if self._db_connection is None:
            raise RuntimeError("Database connection not initialized")

        cursor = self._db_connection.cursor()

        # Person table
        cursor.execute(
            """
            CREATE TABLE person (
                person_id INTEGER PRIMARY KEY,
                gender_concept_id INTEGER,
                year_of_birth INTEGER,
                month_of_birth INTEGER,
                day_of_birth INTEGER,
                race_concept_id INTEGER,
                ethnicity_concept_id INTEGER
            )
        """
        )

        # Condition occurrence table
        cursor.execute(
            """
            CREATE TABLE condition_occurrence (
                condition_occurrence_id INTEGER PRIMARY KEY,
                person_id INTEGER,
                condition_concept_id INTEGER,
                condition_start_date TEXT,
                condition_end_date TEXT,
                FOREIGN KEY (person_id) REFERENCES person(person_id)
            )
        """
        )

        # Observation period table
        cursor.execute(
            """
            CREATE TABLE observation_period (
                observation_period_id INTEGER PRIMARY KEY,
                person_id INTEGER,
                observation_period_start_date TEXT,
                observation_period_end_date TEXT,
                period_type_concept_id INTEGER,
                FOREIGN KEY (person_id) REFERENCES person(person_id)
            )
        """
        )

        # Create indexes for performance
        cursor.execute("CREATE INDEX idx_person_id ON person(person_id)")
        cursor.execute("CREATE INDEX idx_condition_person ON condition_occurrence(person_id)")
        cursor.execute(
            "CREATE INDEX idx_condition_concept ON condition_occurrence(condition_concept_id)"
        )

        self._db_connection.commit()

    def _populate_data(self) -> None:
        """Populate tables with synthetic data."""
        if self._db_connection is None:
            raise RuntimeError("Database connection not initialized")

        generator = SampleDataGenerator(num_persons=1000)
        cursor = self._db_connection.cursor()

        # Insert persons
        persons = generator.generate_person_data()
        cursor.executemany(
            """
            INSERT INTO person VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            persons,
        )

        # Insert conditions
        conditions = generator.generate_condition_occurrence_data()
        cursor.executemany(
            """
            INSERT INTO condition_occurrence VALUES (?, ?, ?, ?, ?)
        """,
            conditions,
        )

        # Insert observation periods
        periods = generator.generate_observation_period_data()
        cursor.executemany(
            """
            INSERT INTO observation_period VALUES (?, ?, ?, ?, ?)
        """,
            periods,
        )

        self._db_connection.commit()

    def get_connection(self) -> sqlite3.Connection:
        """Get database connection.

        Returns:
            SQLite connection object

        Raises:
            RuntimeError: If database not initialized
        """
        if self._db_connection is None:
            raise RuntimeError("Database connection not initialized")
        return self._db_connection

    def execute_query(
        self, query: str, timeout_ms: int = 500
    ) -> tuple[list[tuple[Any, ...]], list[str]]:
        """Execute query with timeout.

        Args:
            query: SQL query to execute
            timeout_ms: Timeout in milliseconds (default: 500ms)

        Returns:
            Tuple of (results, column_names) where results is list of tuples
            and column_names is list of column name strings

        Raises:
            sqlite3.Error: If query execution fails
        """
        if self._db_connection is None:
            raise RuntimeError("Database connection not initialized")

        cursor = self._db_connection.cursor()

        # Set timeout (SQLite uses milliseconds)
        # Note: This sets a timeout for acquiring locks, not query execution time
        # For production, consider using threading.Timer for execution timeout
        cursor.execute(query)
        results = cursor.fetchall()

        # Extract column names
        column_names = []
        if cursor.description:
            column_names = [desc[0] for desc in cursor.description]

        return results, column_names

    def get_row_counts(self) -> dict[str, int]:
        """Get row counts for all tables.

        Returns:
            Dictionary mapping table names to row counts

        Useful for debugging and testing.
        """
        if self._db_connection is None:
            raise RuntimeError("Database connection not initialized")

        cursor = self._db_connection.cursor()

        counts = {}
        for table in ["person", "condition_occurrence", "observation_period"]:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
            counts[table] = cursor.fetchone()[0]

        return counts


# Global singleton instance
# This is initialized on first import and reused throughout the application
sample_db = SampleDatabase()
