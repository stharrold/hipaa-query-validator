"""Sample data generation for query validation testing.

This module provides synthetic OMOP-compliant sample data for Layer 5 validation.
"""

from .generator import SampleDatabase, sample_db

__all__ = ["SampleDatabase", "sample_db"]
