# Changelog

All notable changes to the HIPAA Query Validator project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Layer 7: Prompt Injection Detection** - Pattern-based detection of malicious instructions in SQL queries (#59)
  - Detects instruction keywords in SQL comments and string literals (e.g., "ignore", "disable", "bypass")
  - Blocks privilege escalation attempts (e.g., "admin", "root", "superuser")
  - Identifies encoding/obfuscation patterns (e.g., base64, hex escapes, unicode escapes)
  - Detects 70+ dangerous phrases (e.g., "ignore previous instructions", "disable validation")
  - Educational error messages (E701-E704) explaining why patterns are dangerous
  - Configuration file: `config/prompt_patterns.yaml`
  - Validator module: `src/validators/prompt_injection.py`
  - 45 comprehensive tests with 97% code coverage
  - Fast performance: <5ms overhead per query (p95)
  - Protects against LLM manipulation in text-to-SQL systems
- Total test suite expanded to 158 tests (113 → 158)
- Overall code coverage increased to 87% (85% → 87%)

### Documentation
- Updated README.md to reflect Layer 7 implementation status
- Added Layer 7 error codes documentation (E701-E704)
- Updated validation layers table to show Layer 7 as implemented
- Updated roadmap to show Layer 7 as completed

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
