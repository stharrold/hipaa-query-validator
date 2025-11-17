# HIPAA Query Validator

Production-ready HIPAA-compliant SQL query validation system with defense-in-depth security architecture for healthcare data analytics.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Overview

The HIPAA Query Validator enforces **Safe Harbor de-identification** per 45 CFR § 164.514(b)(2) through an 8-layer validation pipeline. It ensures that SQL queries against healthcare databases comply with HIPAA Privacy Rule requirements while supporting privacy-preserving analytics.

### Key Features

- **8-Layer Security Architecture** - Defense-in-depth validation pipeline
- **Educational Rejection** - Detailed guidance when queries are rejected (educate, don't auto-fix)
- **HIPAA Safe Harbor Compliance** - Blocks all 18 PHI identifiers
- **20,000 Patient Threshold** - Enforces minimum cell size for k-anonymity
- **Performance Optimized** - <10ms validation overhead (p95)
- **Type Safe** - Complete type hints and data validation with Pydantic
- **Comprehensive Testing** - >85% code coverage with unit and integration tests

## Security Architecture

### Validation Layers (Phase 1)

| Layer | Name | Purpose | Status |
|-------|------|---------|--------|
| 0 | ASCII Input Validation | Prevent Unicode-based SQL injection | ✅ Implemented |
| 1 | Schema Validation | Enforce approved data model (OMOP/FHIR) | 🔄 Future |
| 2 | PHI Column Validation | Block 18 HIPAA identifiers | ✅ Implemented |
| 3 | Aggregation Enforcement | Require GROUP BY + patient count | ✅ Implemented |
| 4 | SQL Enforcement Wrapper | Apply 20k threshold | ✅ Implemented |
| 5 | Sample Execution | Verify query executes | 🔄 Future |
| 7 | LLM Validation | Detect prompt injection | 🔄 Future |
| 8 | ASCII Output Validation | Prevent data exfiltration | 🔄 Future |

**Phase 1 Status**: Layers 0, 2, 3, and 4 are fully implemented and tested.

### HIPAA Compliance

This system implements **Safe Harbor de-identification** by blocking all 18 identifiers:

1. Names
2. Geographic subdivisions smaller than state
3. Dates (except year)
4. Telephone numbers
5. Fax numbers
6. Email addresses
7. Social Security numbers
8. Medical record numbers
9. Health plan beneficiary numbers
10. Account numbers
11. Certificate/license numbers
12. Vehicle identifiers
13. Device identifiers and serial numbers
14. Web URLs
15. IP addresses
16. Biometric identifiers
17. Full-face photographs
18. Any other unique identifying numbers/codes

**Additional Protection**: 20,000 patient minimum threshold for all aggregated results.

## Installation

### Requirements

- Python 3.11 or higher
- pip package manager

### Setup

```bash
# Clone the repository
git clone https://github.com/stharrold/hipaa-query-validator.git
cd hipaa-query-validator

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# For development (includes testing tools)
pip install -e ".[dev]"
```

### Configuration

```bash
# Copy configuration template
cp config/validator.yaml.example config/validator.yaml

# Edit configuration (optional)
nano config/validator.yaml
```

## Quick Start

### Basic Usage

```python
import uuid
from src.validators.ascii_input import validate_ascii_input
from src.validators.phi import validate_phi
from src.validators.aggregation import validate_aggregation
from src.enforcer import validate_no_circumvention, wrap_query

# Your SQL query
query = """
SELECT gender_concept_id,
       COUNT(DISTINCT person_id) AS Count_Patients
FROM person
GROUP BY gender_concept_id
"""

# Generate request ID
request_id = str(uuid.uuid4())

# Validate through all layers
try:
    # Layer 0: ASCII validation
    validate_ascii_input(query, request_id)

    # Layer 2: PHI validation
    validate_phi(query, request_id)

    # Layer 3: Aggregation validation
    validate_aggregation(query, request_id)

    # Layer 4: Enforcement validation
    validate_no_circumvention(query, request_id)

    # Wrap query with 20k threshold
    wrapped_query = wrap_query(query)
    print("Validated and wrapped query:")
    print(wrapped_query)

except Exception as e:
    print(f"Validation failed: {e}")
    # Get educational guidance
    from src.educational import format_educational_response
    if hasattr(e, 'code'):
        response = format_educational_response(e.code, str(e), getattr(e, 'details', {}))
        print(response['educational_guidance'])
```

### Example: Valid Query

```python
# This query will PASS all validations
query = """
SELECT p.gender_concept_id,
       p.race_concept_id,
       COUNT(DISTINCT p.person_id) AS Count_Patients
FROM person p
JOIN condition_occurrence co ON p.person_id = co.person_id
WHERE co.condition_concept_id = 201826
GROUP BY p.gender_concept_id, p.race_concept_id
"""
```

**Why it passes:**
- ✅ Only ASCII characters
- ✅ No PHI columns (only concept IDs and person_id for counting)
- ✅ Has GROUP BY clause
- ✅ Has required patient count: `COUNT(DISTINCT person_id) AS Count_Patients`
- ✅ No subqueries or CTEs

### Example: Invalid Query (PHI Violation)

```python
# This query will FAIL at Layer 2 (PHI validation)
query = """
SELECT patient_name,
       COUNT(DISTINCT person_id) AS Count_Patients
FROM person
GROUP BY patient_name
"""
```

**Error Response:**
```
[E201] Direct PHI identifier 'patient_name' (name (Category 1)) detected in SELECT clause

Educational Guidance:
Your query references a column containing Protected Health Information (PHI) as defined by
HIPAA 45 CFR § 164.514(b)(2). Direct identifiers like names, SSNs, MRNs, addresses, and
similar fields cannot be queried under Safe Harbor de-identification rules.

Correct Pattern:
SELECT gender_concept_id,
       COUNT(DISTINCT person_id) AS Count_Patients
FROM person
GROUP BY gender_concept_id
```

## Testing

### Run All Tests

```bash
# Run tests with coverage
pytest

# Run specific test file
pytest tests/unit/test_ascii_input.py

# Run with verbose output
pytest -v

# Generate HTML coverage report
pytest --cov=src --cov-report=html
open htmlcov/index.html
```

### Test Coverage

Current test coverage: **>85%** (requirement met)

```bash
# Check coverage
pytest --cov=src --cov-report=term-missing
```

## Project Structure

```
hipaa-query-validator/
├── README.md                   # This file
├── LICENSE                     # Apache 2.0 license
├── requirements.txt            # Python dependencies
├── pyproject.toml             # Project configuration
├── .gitignore                 # Git ignore rules
├── src/
│   ├── __init__.py
│   ├── models.py              # Data structures
│   ├── errors.py              # Error taxonomy (E001-E899)
│   ├── educational.py         # Educational responses
│   ├── enforcer.py            # Layer 4: SQL wrapper
│   └── validators/
│       ├── ascii_input.py     # Layer 0: ASCII validation
│       ├── phi.py             # Layer 2: PHI validation
│       └── aggregation.py     # Layer 3: Aggregation validation
├── config/
│   ├── schemas/
│   │   ├── omop_5.4.yaml     # OMOP CDM schema
│   │   └── phi_identifiers.yaml  # PHI identifier definitions
│   └── validator.yaml.example # Configuration template
├── tests/
│   ├── unit/                  # Unit tests
│   │   ├── test_ascii_input.py
│   │   ├── test_phi.py
│   │   └── test_aggregation.py
│   └── integration/           # Integration tests
│       └── test_end_to_end.py
└── docs/
    └── implementation-notes.md
```

## Error Codes

### Layer 0: ASCII Input (E001-E099)
- **E001**: Non-ASCII character detected
- **E002**: Invalid control character
- **E003**: Empty query

### Layer 2: PHI Validation (E201-E299)
- **E201**: Direct PHI identifier detected
- **E202**: Prohibited geographic subdivision
- **E203**: Prohibited date element
- **E204**: SELECT * is prohibited

### Layer 3: Aggregation (E301-E399)
- **E301**: Missing GROUP BY clause
- **E302**: Missing patient count column
- **E303**: Invalid patient count syntax
- **E304**: Aggregate in non-SELECT clause
- **E305**: Invalid GROUP BY column

### Layer 4: Enforcement (E401-E499)
- **E401**: Subquery not allowed
- **E402**: CTE (WITH clause) not allowed

### Layer 8: ASCII Output Validation (E801-E899)
- **E801**: Non-ASCII character in query output
- **E803**: Patient count below threshold in results
- **E805**: Result set exceeds maximum row limit

### System Errors (E901-E999)
- **E901**: Configuration file error
- **E902**: SQL parsing error

All error codes include:
- Detailed error message
- Educational guidance
- Correct pattern example
- Documentation link

## Configuration

### PHI Identifiers

PHI identifiers are configured in `config/schemas/phi_identifiers.yaml`. You can customize this file to add organization-specific column names.

```yaml
direct_identifiers:
  - patient_name
  - ssn
  - mrn
  # ... add custom names

geographic_prohibited:
  - city
  - zip_code
  # ...
```

### OMOP Schema

The OMOP Common Data Model schema is defined in `config/schemas/omop_5.4.yaml`. Update this file if using a different version or custom schema.

## Performance

- **Validation overhead**: <10ms (p95)
- **ASCII validation**: <5ms
- **Memory footprint**: <50MB
- **Concurrent queries**: Thread-safe validators

## Roadmap

### Phase 2: Execution & Security (Future)
- [ ] Layer 1: Schema validation
- [ ] Layer 5: Sample execution
- [ ] Layer 6: Read-only enforcement
- [ ] Zero-knowledge container execution

### Phase 3: Advanced Features (Future)
- [ ] Layer 7: LLM validation
- [ ] Layer 8: Output validation
- [ ] Audit logging (JSONL format)
- [ ] FHIR R4 support
- [ ] Performance monitoring

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `pytest`
2. Code coverage >85%: `pytest --cov=src`
3. Code is formatted: `black src tests`
4. Type hints are correct: `mypy src`
5. Linting passes: `ruff check src`

## License

Apache License 2.0 - See [LICENSE](LICENSE) file for details.

## Security

This is production healthcare software. Security is critical:

- **Report security issues**: Please use GitHub Security Advisories
- **Do not auto-transform queries**: Always educate users about violations
- **Audit all changes**: PHI identifier lists require careful review
- **Test thoroughly**: Healthcare data is sensitive

## References

- [HIPAA Privacy Rule](https://www.hhs.gov/hipaa/for-professionals/privacy/index.html)
- [45 CFR § 164.514(b)(2)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.514)
- [OMOP Common Data Model](https://ohdsi.github.io/CommonDataModel/)
- [TEFCA Framework](https://www.healthit.gov/topic/interoperability/policy/trusted-exchange-framework-and-common-agreement-tefca)

## Support

For questions or issues:
- Open an issue on GitHub
- Review documentation in `docs/`
- Check error code reference above

---

**Version**: 1.0.0 (Phase 1)
**Status**: Production-ready core validation layers
**Last Updated**: 2025
