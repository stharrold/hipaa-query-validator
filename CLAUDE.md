# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HIPAA Query Validator is a production-ready SQL query validation system that enforces HIPAA Safe Harbor de-identification requirements (45 CFR § 164.514(b)(2)) through an 8-layer defense-in-depth security architecture. The system is designed for healthcare data analytics, ensuring queries cannot expose Protected Health Information (PHI) while enabling privacy-preserving aggregate analysis.

**Current Status**: Phase 1 complete (v1.0.0) - Layers 0, 2, 3, 4 implemented with 114/114 tests passing and 85%+ coverage.

**Python Requirements**: Python 3.11+ required (uses match statements, StrEnum, improved typing). CI tests on Python 3.11 and 3.12.

**Package Manager**: This project uses `uv` for fast, reliable Python package management. All commands should be prefixed with `uv run` (e.g., `uv run pytest`).

## Core Architecture

### Layered Validation Pipeline

The system uses a **strict sequential validation pipeline** where each layer must pass before proceeding to the next. This design enables fast-fail optimization and clear audit trails.

**Validation Flow:**
```
Query → Layer 0 (ASCII) → Layer 2 (PHI) → Layer 3 (Aggregation) → Layer 4 (Enforcement) → Wrapped Query
```

**Critical Design Principle**: Educational rejection, not auto-transformation. When a query fails validation, provide detailed educational guidance explaining WHY it failed and HOW to fix it. Never silently modify user queries.

### Layer Responsibilities

**Layer 0 - ASCII Input Validation** (`src/validators/ascii_input.py`)
- Enforces ASCII-only characters (0x20-0x7E plus \n\r\t)
- Prevents Unicode-based SQL injection attacks
- Performance: <5ms for typical queries
- Error codes: E001-E099

**Layer 2 - PHI Column Validation** (`src/validators/phi.py`)
- Blocks all 18 HIPAA Safe Harbor PHI identifier categories
- Uses recursive sqlparse token checking
- Validates SELECT, WHERE, ON, HAVING, GROUP BY clauses
- Configuration: `config/schemas/phi_identifiers.yaml`
- Error codes: E201-E299

**Layer 3 - Aggregation Enforcement** (`src/validators/aggregation.py`)
- Requires exact syntax: `COUNT(DISTINCT person_id) AS Count_Patients`
- Enforces GROUP BY for non-global aggregates
- Distinguishes aliased aggregates from regular columns
- Error codes: E301-E399

**Layer 4 - SQL Enforcement** (`src/enforcer.py`)
- Applies 20,000 patient minimum threshold via SQL wrapper
- Blocks subqueries and CTEs (anti-circumvention)
- Wrapper executes AFTER user's WHERE clause
- Error codes: E401-E499

### Critical Implementation Details

**Exact Patient Count Syntax Requirement:**
The system requires EXACTLY `COUNT(DISTINCT person_id) AS Count_Patients` with:
- Case-insensitive keywords except alias
- Alias must be exactly `Count_Patients` (case-sensitive)
- No variations allowed (enables reliable SQL wrapper enforcement)

**Hybrid Detection Strategy (sqlparse limitations):**
Because `sqlparse` is not a full SQL grammar parser, validators use a hybrid approach:
- Token-based parsing for structure identification
- Regex patterns as fallback for pattern matching
- String-based detection for keywords (e.g., `"GROUP BY" in query.upper()`)

**Example from aggregation.py:**
```python
# Token-based: Check parsed tokens
if isinstance(token, Identifier):
    self._check_identifier(token, clause)

# Regex fallback: Handle whitespace variations
if re.search(r'GROUP\s+BY', statement_str):
    self.has_group_by = True
```

## Development Commands

### Setup

```bash
# Install dependencies (first time setup)
uv pip install -e ".[dev]"
```

### Testing

```bash
# Run all tests with coverage (enforces >=85% coverage requirement)
uv run pytest

# Run specific test file
uv run pytest tests/unit/test_phi.py

# Run single test
uv run pytest tests/unit/test_phi.py::TestDirectPHIIdentifiers::test_patient_name

# Run with verbose output
uv run pytest -v

# Generate HTML coverage report
uv run pytest --cov=src --cov-report=html
open htmlcov/index.html

# Run tests without coverage checks
uv run pytest --no-cov
```

### Code Quality

```bash
# Format code (line length: 100)
uv run black src tests

# Type checking (strict mode enabled)
uv run mypy src

# Linting
uv run ruff check src tests

# Run all quality checks
uv run black src tests && uv run mypy src && uv run ruff check src tests && uv run pytest
```

### Configuration

**PHI Identifiers**: `config/schemas/phi_identifiers.yaml`
- Defines all 18 HIPAA Safe Harbor identifier categories
- Used by Layer 2 (PHI validation)
- When adding custom PHI patterns:
  1. Add to appropriate category (direct_identifiers, geographic_prohibited, date_prohibited)
  2. Use lowercase (validator normalizes to lowercase)
  3. Run full test suite to ensure no false positives
  4. Consider HIPAA compliance implications

**OMOP Schema**: `config/schemas/omop_5.4.yaml`
- OMOP CDM 5.4 table and column definitions
- Reserved for future Layer 1 (schema validation)
- Not currently enforced in v1.0.0

**Validator Settings**: `config/validator.yaml.example`
- Security: min_patient_count (20000), strict_mode
- Performance: max_query_length, timeouts
- Audit logging: JSONL output paths
- Educational: verbosity levels
- Deployment: development vs. production modes

### Issue Closure Protocol

**CRITICAL**: Before closing ANY GitHub issue, complete this 5-point verification checklist:

**1. Linked Pull Request**
- [ ] PR is linked to the issue (#PR_NUMBER in issue description or comment)
- [ ] PR is merged to main branch
- [ ] Closing comment includes: `Closes #ISSUE via PR #NUMBER`

**2. Test Requirements**
- [ ] Run: `uv run pytest` (all 114 tests pass)
- [ ] Run: `uv run pytest --cov=src` (coverage ≥85%)
- [ ] No test failures or skipped tests
- [ ] New code has ≥95% line coverage

**3. Code Review**
- [ ] PR has at least one approval
- [ ] All review comments addressed
- [ ] Security/HIPAA review completed (if applicable)

**4. Documentation Updates**
- [ ] CHANGELOG.md updated with issue reference
- [ ] README.md sections reviewed and updated (if applicable)
- [ ] CLAUDE.md sections reviewed and updated (if applicable)
- [ ] Code comments and docstrings added

**5. Functional Verification**
- [ ] Original issue reproduced and verified fixed
- [ ] No regressions introduced
- [ ] HIPAA compliance maintained (for validator changes)

**Closure Comment Template:**
```markdown
## Closure Summary

### What Was Fixed
[Brief description of the fix]

### Verification Completed
- Tests: All 114 tests pass with 85%+ coverage
- Review: Approved by @reviewer_name
- Docs: CHANGELOG.md and [other docs] updated
- Functional: Tested with [describe scenario]

Closes #ISSUE via PR #NUMBER
```

**Quality Gates:**
- Healthcare software requires high standards
- HIPAA audit trail requires traceability
- Closure without verification risks compliance violations

## Testing Requirements

**Critical Constraints:**
- Maintain 100% test pass rate (114/114 tests)
- Maintain >=85% code coverage
- No breaking changes to existing functionality
- Test after EACH code change

**Test Organization:**
```
tests/
├── unit/                    # Isolated component tests (97 tests)
│   ├── test_ascii_input.py  # 29 ASCII validation tests
│   ├── test_phi.py          # 40 PHI validation tests
│   └── test_aggregation.py  # 28 aggregation tests
└── integration/             # End-to-end workflows (17 tests)
    └── test_end_to_end.py   # Full validation pipeline
```

**When modifying validators:**
1. Read existing test file first to understand patterns
2. Add new test cases for new behavior
3. Run affected test file: `uv run pytest tests/unit/test_<layer>.py -v`
4. Run full suite: `uv run pytest`
5. Verify coverage maintained: Check pytest output for coverage percentage

## CI/CD Automation

**GitHub Actions Workflows:**

**`.github/workflows/tests.yml`** - Automated Testing Pipeline
- Triggers on pull requests to `develop` or `main` branches
- Runs on Python 3.11 and 3.12 (matrix strategy)
- Executes all quality checks: black, mypy, ruff, pytest
- Enforces >=85% code coverage requirement
- Uses `uv` for dependency management
- Uploads HTML coverage reports as artifacts

**`.github/workflows/claude.yml`** - Claude Code Integration
- Triggers on @claude mentions in issues/PRs
- Enables Claude to respond to development requests
- Has read access to issues, PRs, and CI results

**`.github/workflows/claude-code-review.yml`** - Automated PR Reviews
- Triggers on new PRs or PR updates
- Claude performs automated code review
- Reviews code quality, security, performance, test coverage
- Posts review comments directly on PRs

## Error Taxonomy

All errors follow a hierarchical structure with educational guidance:

```
ValidationError (base)
├── ASCIIValidationError (E001-E099)
│   ├── NonASCIICharacterError (E001)
│   ├── InvalidControlCharacterError (E002)
│   └── EmptyQueryError (E003)
├── PHIValidationError (E201-E299)
│   ├── DirectPHIIdentifierError (E201)
│   ├── GeographicPHIError (E202)
│   ├── DatePHIError (E203)
│   └── SelectStarError (E204)
├── AggregationError (E301-E399)
│   ├── MissingGroupByError (E301)
│   ├── MissingPatientCountError (E302)
│   ├── InvalidPatientCountSyntaxError (E303)
│   ├── AggregateInNonSelectError (E304)
│   └── InvalidGroupByColumnError (E305)
└── EnforcementError (E401-E499)
    ├── SubqueryNotAllowedError (E401)
    └── CTENotAllowedError (E402)
```

**When adding new error types:**
1. Choose appropriate error code in correct range
2. Inherit from appropriate base class
3. Include educational guidance in `src/educational.py`
4. Add test case verifying error is raised correctly
5. Document in README.md error codes section

## Common Patterns

### Adding a New PHI Identifier

```python
# 1. Add to config/schemas/phi_identifiers.yaml
direct_identifiers:
  - new_phi_column_name  # lowercase

# 2. Add test in tests/unit/test_phi.py
def test_new_phi_identifier(self):
    query = "SELECT new_phi_column_name FROM person"
    with pytest.raises(DirectPHIIdentifierError):
        validate_phi(query, "test-xxx")

# 3. Run tests
uv run pytest tests/unit/test_phi.py -v
```

### Modifying Validation Logic

```python
# 1. Read the validator file to understand current logic
# 2. Locate the specific validation method
# 3. Make changes following existing patterns
# 4. Update or add tests
# 5. Run: uv run pytest tests/unit/test_<validator>.py
# 6. Run full suite: uv run pytest
```

### Debugging sqlparse Token Structure

```python
import sqlparse

query = "SELECT gender_concept_id FROM person"
parsed = sqlparse.parse(query)
for statement in parsed:
    for token in statement.tokens:
        print(f"{type(token).__name__}: {repr(token)} | ttype={token.ttype}")
        if hasattr(token, 'tokens'):
            for subtoken in token.tokens:
                print(f"  {type(subtoken).__name__}: {repr(subtoken)}")
```

## HIPAA Compliance Notes

**Safe Harbor Requirements:**
- Block all 18 PHI identifier categories (enforced by Layer 2)
- Minimum 20,000 patient threshold (enforced by Layer 4 wrapper)
- No automatic query transformation (educational rejection only)
- Audit trail of all validation decisions

**Anti-Circumvention Measures:**
- Exact patient count syntax prevents alias spoofing
- Subquery/CTE prohibition prevents nested COUNT manipulation
- SQL wrapper executes AFTER user WHERE clause
- Multiple overlapping validation layers

**Security Philosophy:**
Never trust user input. Validate at multiple layers. Educate users when validation fails rather than silently modifying queries. Maintain clear audit trail for compliance.

## Known Limitations

- `sqlparse` is not a full SQL grammar parser (may miss edge cases)
- PHI identifier list may need organization-specific customization
- ASCII-only enforcement prevents legitimate international text (by design)
- Performance degrades linearly with query length (consider max length limit)

## Future Phases (Not Yet Implemented)

- Layer 1: Schema validation (OMOP table/column checking)
- Layer 5: Sample query execution
- Layer 6: Read-only enforcement
- Layer 7: LLM validation for prompt injection
- Layer 8: ASCII output validation
- Audit logging to JSONL
- Container-based execution environment
