# Issue Closure Protocol

This document defines the verification checklist that must be completed before closing any issue in the HIPAA Query Validator repository. Following this protocol ensures code quality, maintains documentation accuracy, and preserves HIPAA compliance standards.

## Closure Overview

Before an issue can be closed, the following five categories must be verified and all requirements must be met:

1. **Linked Pull Request** - Issue references the fixing PR
2. **Test Requirements** - All tests pass with adequate coverage
3. **Code Review** - PR has been reviewed and approved
4. **Documentation Updates** - Related docs are current
5. **Functional Verification** - Fix actually resolves the issue

## 1. Linked Pull Request

**Requirement**: Every closed issue MUST reference the pull request that fixed it.

### Verification Steps

1. **Check PR Link Exists**
   - Navigate to the issue on GitHub
   - Verify "Linked pull requests" section shows at least one PR
   - If no PR is linked, request the PR author link the issue

2. **PR Link Format**
   - Use GitHub's native PR linking (type `#PR_NUMBER` in issue description or comment)
   - Include the PR link in the closing comment before merging
   - Example closing message:
     ```
     Closes #12 via PR #45
     ```

3. **Status Check**
   - Confirm the linked PR is merged (not just open)
   - If PR is still in draft or under review, do NOT close the issue
   - Verify PR is merged to main/master branch

### Why This Matters

- **Audit Trail**: Enables traceability from issue to fix
- **Historical Reference**: Allows future review of decision rationale
- **Compliance**: Required for HIPAA audit documentation

## 2. Test Requirements

**Requirement**: All tests must pass AND code coverage must meet minimum thresholds before closing any issue.

### Verification Steps

1. **Run Full Test Suite**
   ```bash
   pytest
   ```
   - Output should show: `110 passed` (current test count)
   - No failures, errors, or skipped tests
   - If any test fails, do NOT close the issue

2. **Verify Code Coverage**
   ```bash
   pytest --cov=src --cov-report=term-missing
   ```
   - Coverage MUST be ≥85% (project requirement)
   - Check coverage report for any new lines below 85%
   - New code should have ≥95% line coverage

3. **Run Specific Test File (Optional)**
   - If issue relates to specific validation layer:
     ```bash
     pytest tests/unit/test_<layer>.py -v
     ```
   - Examples:
     - `pytest tests/unit/test_ascii_input.py -v`
     - `pytest tests/unit/test_phi.py -v`
     - `pytest tests/unit/test_aggregation.py -v`

4. **Integration Tests**
   ```bash
   pytest tests/integration/test_end_to_end.py -v
   ```
   - Verify end-to-end validation pipeline still works
   - No regression in integration test coverage

### Acceptable Test Results

| Status | Closing Allowed? |
|--------|-----------------|
| All tests pass, ≥85% coverage | ✅ Yes |
| All tests pass, <85% coverage | ❌ No |
| 1+ test failures | ❌ No |
| Coverage dropped from previous level | ❌ No |
| New code with <95% coverage | ❌ No |

### Why This Matters

- **Quality Assurance**: Tests verify the fix actually works
- **Regression Prevention**: Ensures no unintended side effects
- **Compliance**: Healthcare software requires high code quality
- **Coverage Requirement**: 85% minimum is project mandate

## 3. Code Review Requirements

**Requirement**: All code changes must be reviewed and approved before the issue can be closed.

### Verification Steps

1. **Review Approval Status**
   - Navigate to the linked PR
   - Check "Reviewers" section in PR details
   - Verify at least one reviewer has approved (green checkmark)

2. **Review Types to Check**
   - [ ] **Functional Review**: Does code solve the stated problem?
   - [ ] **Security Review**: No new vulnerabilities introduced?
   - [ ] **HIPAA Review**: Complies with Safe Harbor requirements?
   - [ ] **Code Quality Review**: Follows project style and patterns?
   - [ ] **Testing Review**: Tests adequately cover changes?

3. **Required Reviewers (if applicable)**
   - For HIPAA-related changes: Security/compliance review required
   - For validator changes: PHI detection or aggregation expert required
   - For API changes: Architecture/design review required

4. **Address Review Comments**
   - All requested changes must be completed
   - Comments must be resolved (not just dismissed)
   - Additional commits addressing feedback must be in the PR
   - Re-approval may be needed after significant changes

### Review Checklist for Reviewers

Before approving, reviewers should verify:

```
Security & Compliance
- [ ] No PHI accidentally exposed in examples
- [ ] HIPAA Safe Harbor rules still enforced
- [ ] No SQL injection vulnerabilities introduced
- [ ] Configuration defaults are secure

Code Quality
- [ ] Follows project style (Black formatting)
- [ ] Type hints complete and correct (mypy)
- [ ] Linting passes (ruff check)
- [ ] No dead code or debugging statements

Functionality
- [ ] Issue requirements are fully addressed
- [ ] No unintended side effects
- [ ] Backwards compatible (or breaking change documented)
- [ ] Error messages are educational and helpful

Testing
- [ ] Tests pass locally
- [ ] Coverage meets 85% minimum
- [ ] New functionality has >95% line coverage
- [ ] Edge cases are tested
```

### Why This Matters

- **Knowledge Sharing**: Review spreads understanding of codebase
- **Security Gate**: Additional eyes catch vulnerabilities
- **Quality Enforcement**: Prevents substandard code from merging
- **Compliance**: Code review is HIPAA audit requirement

## 4. Documentation Updates

**Requirement**: All relevant documentation must be updated to reflect the fix.

### Documentation Checklist

#### A. CHANGELOG.md (If exists)

- [ ] Issue number added to appropriate version section
- [ ] Brief description of fix in changelog format
- [ ] Category identified (Bug Fix, Feature, Enhancement, etc.)

Example entry:
```markdown
### Fixed
- [#12] Fixed issue with batch closure protocol validation
```

#### B. README.md

Check if any of these sections need updates:

- [ ] **Installation**: New dependencies added?
- [ ] **Configuration**: New config options?
- [ ] **Error Codes**: New error codes introduced?
- [ ] **Project Structure**: New files added?
- [ ] **Contributing**: Process changes?
- [ ] **Examples**: New examples needed?

#### C. CLAUDE.md

Check if any of these sections need updates:

- [ ] **Core Architecture**: Layer changes documented?
- [ ] **Layer Responsibilities**: New layer or modified layer?
- [ ] **Error Taxonomy**: New error codes?
- [ ] **Testing Requirements**: Test requirements changed?
- [ ] **Development Commands**: New commands needed?
- [ ] **Known Limitations**: New limitations discovered?

#### D. Code Comments

- [ ] Complex logic has explanatory comments
- [ ] Why (not just what) is explained
- [ ] Links to HIPAA requirements included where relevant
- [ ] Architecture decisions documented

#### E. In-Code Documentation

- [ ] Docstrings on all public functions
- [ ] Type hints complete
- [ ] Error handling documented
- [ ] Configuration options documented

### Documentation Quality Standards

Documentation must meet these standards:

| Aspect | Standard |
|--------|----------|
| **Clarity** | Clear to someone unfamiliar with this code |
| **Completeness** | All public APIs documented |
| **Accuracy** | Matches actual behavior exactly |
| **Updates** | Reflects all changes from PR |
| **Links** | References to related docs/issues |
| **Examples** | Code examples (if applicable) work correctly |

### Why This Matters

- **Onboarding**: New contributors need clear documentation
- **Maintenance**: Future you will thank present you
- **Compliance**: Audit trail of changes
- **User Guidance**: Users understand how to use the system

## 5. Functional Verification

**Requirement**: The actual fix must be verified to work in practice, not just in theory.

### Verification Approach

#### For Bug Fixes

1. **Reproduce Original Issue**
   - Set up test environment with original code
   - Verify bug is reproducible (if possible)
   - Document reproduction steps

2. **Apply Fix**
   - Checkout PR branch
   - Run reproduction steps
   - Verify issue is resolved

3. **Test Edge Cases**
   - Test with edge case inputs
   - Test with various query complexities
   - Verify no regressions

#### For Feature Additions

1. **Feature Completeness**
   - All stated features from issue are present
   - Features work as specified
   - No half-implemented features

2. **Integration Testing**
   - Feature integrates cleanly with existing code
   - No conflicts with other features
   - API is consistent with project conventions

3. **User Experience**
   - Error messages are clear
   - Educational guidance is helpful
   - Performance is acceptable

#### For Validator Changes

1. **Security Verification**
   - False negatives check: Can attackers bypass validation?
   - False positives check: Are legitimate queries rejected?
   - PHI protection: All 18 HIPAA identifiers still protected?

2. **Performance Verification**
   - Validation still <10ms for typical queries
   - Memory usage acceptable
   - No performance regression

3. **Compliance Verification**
   - Maintains Safe Harbor de-identification
   - Enforces 20,000 patient minimum threshold
   - No HIPAA compliance violations

### Functional Testing Checklist

Before closing, verify:

```
General Functionality
- [ ] Fix addresses the stated issue
- [ ] No unintended side effects
- [ ] Integration with other layers works
- [ ] Performance is acceptable

Query Validation (if applicable)
- [ ] Valid queries pass validation
- [ ] Invalid queries are rejected
- [ ] Error messages are educational
- [ ] Correct error codes returned

HIPAA Compliance (for any validator changes)
- [ ] All 18 PHI identifiers still detected
- [ ] Safe Harbor requirements maintained
- [ ] No de-identification bypasses
- [ ] Threshold enforcement working

Edge Cases
- [ ] Large queries handled correctly
- [ ] Complex nested queries handled
- [ ] Unusual but valid SQL accepted
- [ ] Malformed input rejected safely
```

### Why This Matters

- **Real-World Validation**: Tests don't catch everything
- **User Protection**: Healthcare data is sensitive
- **Compliance Assurance**: HIPAA requires actual verification
- **Confidence**: Know the fix really works

## Complete Closure Checklist

Use this comprehensive checklist when closing any issue:

```markdown
## Closure Verification Checklist

### 1. Linked Pull Request
- [ ] PR is linked to this issue
- [ ] PR is merged to main branch
- [ ] PR link included in closing comment

### 2. Test Requirements
- [ ] Run: pytest (all tests pass)
- [ ] Run: pytest --cov=src (coverage ≥85%)
- [ ] No test failures or skipped tests
- [ ] Coverage report reviewed

### 3. Code Review
- [ ] PR has at least one approval
- [ ] All review comments addressed
- [ ] Re-approval obtained if changes made post-review
- [ ] Security/HIPAA review (if applicable) completed

### 4. Documentation Updates
- [ ] CHANGELOG.md updated (if applicable)
- [ ] README.md sections reviewed and updated
- [ ] CLAUDE.md sections reviewed and updated
- [ ] Code comments and docstrings added
- [ ] Examples tested and validated

### 5. Functional Verification
- [ ] Original issue reproduced (if possible)
- [ ] Fix resolves the issue
- [ ] No regressions introduced
- [ ] Edge cases tested
- [ ] HIPAA compliance verified (if validator change)
- [ ] Performance acceptable

### Closing Statement

[Provide a brief summary of what was fixed and how it was verified]

Closes #[ISSUE_NUMBER] via PR #[PR_NUMBER]
```

## Special Cases

### Breaking Changes

If the issue resolution includes breaking changes:

1. **Document Breaking Changes**
   - List all breaking changes in PR description
   - Explain migration path for users
   - Update CHANGELOG with migration instructions

2. **Version Bump**
   - Update version number (MAJOR.minor.patch)
   - Follow semantic versioning

3. **Deprecation Period (if applicable)**
   - Provide grace period if possible
   - Clearly warn users of deprecation
   - Document timeline for removal

### Security Fixes

If the issue is security-related:

1. **Security Review Required**
   - Senior reviewer approval required
   - Security testing completed
   - No security details in public PR (if sensitive)

2. **Update Security Advisories**
   - File CVE if applicable
   - Document security impact
   - Update security.md

3. **Comprehensive Testing**
   - Penetration testing (if applicable)
   - No alternative bypass methods
   - Regression testing essential

### HIPAA Compliance Changes

If the issue affects HIPAA compliance:

1. **Compliance Review Required**
   - Legal/compliance team review (if available)
   - Verify Safe Harbor requirements met
   - Document compliance rationale

2. **Audit Trail Documentation**
   - Track decision reasoning
   - Document HIPAA requirements addressed
   - Reference 45 CFR § 164.514(b)(2)

3. **Testing Requirements**
   - Test with healthcare data samples (sanitized)
   - Verify de-identification effectiveness
   - No false negatives (attacks bypass validation)

## Closure Comment Template

When closing an issue, use a comment like this:

```markdown
## Closure Summary

### What Was Fixed
[Brief description of the fix]

### Verification Completed
- Tests: All 110 tests pass with 85%+ coverage
- Review: Approved by @reviewer_name on [DATE]
- Docs: README.md, CLAUDE.md, and CHANGELOG.md updated
- Functional: Tested with [DESCRIBE TEST SCENARIO]

### PR Reference
Closes #[ISSUE_NUMBER] via PR #[PR_NUMBER]
```

## Preventing Premature Closure

An issue should NOT be closed if:

| Condition | Action |
|-----------|--------|
| No PR linked | Request PR link or ask for PR to be created |
| Tests failing | Return to development, fix test failures |
| Coverage below 85% | Develop additional tests to reach threshold |
| No review approval | Wait for reviewer to approve, address feedback |
| Docs not updated | Update docs before closing |
| Fix not verified | Perform functional verification |
| Breaking changes undocumented | Add migration guide and version bump |

## Questions & Escalation

If unsure about closure requirements:

- **Test Coverage Questions**: Check with test author or CLAUDE.md
- **Documentation Scope**: Review similar closed issues
- **HIPAA Compliance**: Escalate to compliance reviewer
- **Architecture Changes**: Discuss with maintainers
- **Security Concerns**: Escalate to security reviewer

## Related Documents

- [CLAUDE.md](./CLAUDE.md) - Project guidelines for Claude Code
- [README.md](./README.md) - Project overview and setup
- Contributing guidelines (if available)
- GitHub Security Policy (if available)

---

**Last Updated**: 2025
**Version**: 1.0
**Status**: Active
