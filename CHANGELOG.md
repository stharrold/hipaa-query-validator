# Changelog

All notable changes to the HIPAA Query Validator project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/stharrold/hipaa-query-validator/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/stharrold/hipaa-query-validator/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/stharrold/hipaa-query-validator/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/stharrold/hipaa-query-validator/releases/tag/v1.1.0
