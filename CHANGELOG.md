# Changelog

All notable changes to the HIPAA Query Validator project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/stharrold/hipaa-query-validator/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/stharrold/hipaa-query-validator/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/stharrold/hipaa-query-validator/releases/tag/v1.1.0
