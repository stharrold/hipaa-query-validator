# Changelog

All notable changes to the HIPAA Query Validator project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- HIPAA-compliant audit logging system (#62)
  - JSONL event format with one event per line
  - HMAC-SHA256 log signing for tamper detection
  - Query hashing (SHA-256) to prevent PHI exposure in logs
  - Time-based log rotation with 6-year retention (HIPAA requirement)
  - Comprehensive event tracking: validation, errors, security events
  - Performance: <5ms overhead per event
  - Three event types: QUERY_VALIDATION, VALIDATION_ERROR, SECURITY_EVENT
  - Singleton logger pattern for consistent application-wide logging
  - Environment-based signing key configuration
  - Detailed audit configuration file (config/audit.yaml.example)
- Unified validator module (src/validator.py)
  - Main entry point for query validation with integrated audit logging
  - Sequential validation pipeline: Layer 0 → 2 → 3 → 4
  - Performance tracking for each validation layer
  - Automatic security event detection for circumvention attempts
  - Support for user_id, session_id, ip_address, container_id tracking
  - Silent validation mode for internal use without audit logging

### Testing
- Added 63 new audit logging tests (test_audit_logger.py)
  - Query hashing tests (5 tests)
  - Event creation tests (11 tests)
  - JSONL formatter tests (3 tests)
  - Audit logger tests (7 tests)
  - Performance tests (2 tests)
  - Field validation tests (3 tests)
- Added 15 new validator integration tests (test_validator.py)
  - Request ID generation tests
  - Valid query validation tests (3 tests)
  - Invalid query validation tests (6 tests)
  - Audit logging integration tests (4 tests)
  - Performance tracking tests (3 tests)
  - Silent validation tests (3 tests)
- All 191 tests passing (113 original + 78 new)
- Code coverage maintained at ≥85%

### Documentation
- Added comprehensive audit logging configuration (config/audit.yaml.example)
  - HIPAA compliance settings (6-year retention)
  - Security settings (HMAC signing, permissions)
  - Privacy settings (query hashing, no full query logging)
  - Production deployment guidelines
  - Key generation and rotation instructions

## [1.2.2] - 2025-11-17

### Fixed
- Enhanced CI/CD testing workflow for improved reliability (#44, #45, #47)
  - Pinned uv version to 0.5.0 for reproducible builds
  - Replaced curl installation with astral-sh/setup-uv@v1 action (improved security)
  - Added explicit workflow permissions (contents: read, pull-requests: read)
  - Added --diff flag to black check for better diagnostics on failures
  - Follows principle of least privilege for HIPAA audit compliance
- Updated package dependencies in uv.lock (#52)

### Documentation
- Verified and confirmed test counts in CLAUDE.md are correct at 113 tests (#30)
- Verified and confirmed test count in CHANGELOG.md is correct (#29)
- Verified and confirmed no date typos in CHANGELOG.md (#25)
- Verified import re statement exists in src/enforcer.py (#26)

## [1.2.1] - 2025-11-17

### Documentation
- Added comprehensive Release Workflow section to CLAUDE.md (#49)
  - Documented branch strategy (main, develop, contrib/*, release/*)
  - Added 7-step release process with commands
  - Included semantic versioning guidelines
  - Provides repeatable release workflow for future releases
- Updated CLAUDE.md version reference from v1.0.0 to v1.2.0
- Made OMOP schema documentation version-agnostic

## [1.2.0] - 2025-11-17

### Added
- Automated CI/CD testing pipeline with GitHub Actions
  - Tests on Python 3.11 and 3.12 (matrix strategy)
  - Runs black, mypy, ruff, and pytest on all PRs
  - Enforces >=85% code coverage requirement
  - Uploads HTML coverage reports as artifacts
- Package manager integration with `uv`
  - Added uv.lock for reproducible dependency management
  - All development commands now use `uv run` prefix
- Python version requirements documentation (Python 3.11+ required)

### Fixed
- Corrected test count documentation from 114 to actual 113 tests (#38, #39)
  - ASCII: 29 tests
  - PHI: 39 tests (corrected from 40)
  - Aggregation: 28 tests
  - Integration: 17 tests

### Documentation
- Consolidated ISSUE_CLOSURE_PROTOCOL.md into CLAUDE.md (#12, #31, #32)
  - Improved discoverability for AI agents and developers
  - Single source of truth for development guidelines
- Added comprehensive CI/CD documentation section
- Added setup instructions for uv package manager
- Updated all command examples to use `uv run` prefix

## [1.1.1] - 2024-11-16

### Fixed
- Fixed potential false positives in PHI detection from string literals (#14)
  - String literal values containing PHI patterns are now correctly skipped during validation
  - Prevents false PHI violations when queries use legitimate string values like 'email' or 'patient_name'
- Added defensive programming check for token attribute access (#15)
  - Added `hasattr` check before accessing `token.is_whitespace` to prevent potential AttributeError

### Improved
- Optimized regex compilation for better performance (#20)
  - GROUP_BY pattern in aggregation validator compiled at module level
  - SUBQUERY pattern in enforcer compiled at module level
  - Reduces repeated compilation overhead during query validation

### Documentation
- Updated test count in CLAUDE.md to reflect actual 39 PHI validation tests (#18)
- Improved test docstring accuracy for PHI detection tests (#13, #19)
- Added comprehensive docstring documentation with Raises sections (#16)
- Integrated issue closure protocol into CLAUDE.md for easier maintenance (#12, #31, #32)
  - Consolidated verification checklist from standalone protocol document
  - Ensures AI agents see closure guidance during development

### Testing
- Added comprehensive test coverage for string literal handling
- All 113 tests passing
- Code coverage maintained at 85%+

## [1.1.0] - 2024-11-16

### Added
- Phase 1 implementation complete with 4-layer validation architecture
- Layers 0, 2, 3, 4 implemented with full test coverage
- 113 tests with 85%+ code coverage
- HIPAA Safe Harbor compliance enforcement
- Educational error messaging system

[Unreleased]: https://github.com/stharrold/hipaa-query-validator/compare/v1.2.2...HEAD
[1.2.2]: https://github.com/stharrold/hipaa-query-validator/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/stharrold/hipaa-query-validator/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/stharrold/hipaa-query-validator/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/stharrold/hipaa-query-validator/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/stharrold/hipaa-query-validator/releases/tag/v1.1.0
