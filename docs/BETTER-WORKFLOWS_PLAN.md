# GitHub Actions Workflows Improvement Plan

## Current State Analysis

The project has 10 workflow files handling building, testing, releasing, and maintaining code quality:

1. **build.yml** - Snapshot build validation with GoReleaser
2. **build-win.yml** - Separate Windows release workflow
3. **ci.yml** - Comprehensive CI with cross-platform Linux testing
4. **go.yml** - Go linting and unit tests
5. **gha.yml** - GitHub OIDC provider integration test
6. **release.yml** - Production releases via GoReleaser
7. **cli-docs.yml** - Auto-generate CLI documentation
8. **zizmor.yml** - Security scanning
9. **staging.yml** - Code coverage reporting
10. **release-drafter.yml** - Auto-draft release notes

---

## 🚨 Major Issues

### 0. Workflows Don't Run on Branch Pushes ⚠️ CRITICAL (FORK ISSUE)
**Problem**: Workflows only trigger on PRs or pushes to `main`, not on regular branch pushes. This is extremely unfriendly for fork development:
- Fork developers push to their branches but no CI runs
- They don't know if their changes break anything until creating a PR
- Slow feedback loop discourages testing

**Impact**: Poor developer experience, delayed bug detection, discourages contributions

**Solution**: Update workflow triggers to run on all branch pushes:
```yaml
on:
  pull_request:
  push:
    branches:
      - '**'  # Run on all branches
```

**Status**: ✅ FIXED - All main workflows now run on all branch pushes

### 1. Duplicate Windows Release Logic ⚠️ CRITICAL
**Problem**: Two separate workflows handle Windows releases:
- `build-win.yml` builds Windows binaries manually with PowerShell scripts
- `release.yml` uses GoReleaser but ignores Windows ARM64

**Impact**: Maintenance overhead, potential inconsistencies, wasted CI resources

**Solution**: Consolidate into GoReleaser:
- Enable Windows ARM64 in `.goreleaser.yaml`
- Configure GoReleaser to include PowerShell installation scripts
- Remove `build-win.yml`

### 2. No Windows Testing ⚠️ HIGH
**Problem**: All integration tests run on Linux (Ubuntu, CentOS, Arch, OpenSUSE). No Windows testing despite Windows being a supported platform.

**Impact**: Windows-specific bugs may not be caught before release

**Solution**: Add Windows runner to CI matrix with appropriate test adaptations

### 3. Redundant Go Testing
**Problem**: Tests run in 3 separate workflows:
- `go.yml` - unit tests on PR
- `ci.yml` - integration tests
- `staging.yml` - coverage on push to main

**Solution**: Consolidate testing strategy with coverage collection in CI workflow

### 4. Misleading Workflow Names
**Problem**:
- `staging.yml` named "Go Checks" but performs coverage reporting
- `gha.yml` doesn't clearly indicate it tests GitHub OIDC

**Solution**: Rename for clarity:
- `staging.yml` → `coverage.yml` (name: "Code Coverage")
- `gha.yml` → `github-oidc-test.yml` (name: "GitHub OIDC Integration Test")

---

## 🎯 Improvement Roadmap

### Phase 0: Fork-Friendly Workflows (COMPLETED ✅)
- [x] **Item 0**: Enable workflows on all branch pushes
  - Updated `ci.yml` to run on all branches
  - Updated `build.yml` to run on all branches  
  - Updated `go.yml` to run on all branches with Go changes
  - Updated `zizmor.yml` to run on all branches
  - **Impact**: Fork developers get immediate CI feedback

### Phase 1: Windows Support (PRIORITY)
- [ ] **Item 1**: Consolidate Windows build logic
  - Enable Windows ARM64 in GoReleaser
  - Add PowerShell scripts to GoReleaser releases
  - Remove `build-win.yml` workflow
  
- [ ] **Item 2**: Add Windows testing to CI
  - Add Windows runner to test matrix
  - Adapt integration tests for Windows
  - Ensure cross-platform compatibility

### Phase 2: Testing Optimization
- [ ] **Item 3**: Consolidate test workflows
  - Merge coverage collection into main CI
  - Eliminate redundant test runs
  - Optimize test execution time

- [ ] **Item 4**: Add macOS testing (future)
  - Add macOS runner to test matrix
  - Validate macOS builds work correctly

### Phase 3: Security & Dependencies
- [ ] **Item 5**: Add dependency review workflow
  - Scan for vulnerable dependencies on PRs
  - Automated security alerts

- [ ] **Item 6**: Update action versions
  - Review and update pinned action versions
  - Maintain security best practices

### Phase 4: Release Validation
- [ ] **Item 7**: Add release smoke tests
  - Validate binaries work after release
  - Test on all supported platforms
  - Catch release packaging issues

### Phase 5: Documentation & Naming
- [ ] **Item 8**: Rename misleading workflows
  - Clear, descriptive workflow names
  - Consistent naming conventions

- [ ] **Item 9**: Add workflow documentation
  - Document purpose of each workflow
  - Include trigger conditions and dependencies

### Phase 6: Performance
- [ ] **Item 10**: Optimize caching
  - Cache Go dependencies effectively
  - Cache GoReleaser builds
  - Reduce CI execution time

- [ ] **Item 11**: Parallel execution
  - Remove unnecessary job dependencies
  - Enable concurrent execution where safe

- [ ] **Item 12**: Conditional job execution
  - Skip jobs when files haven't changed
  - Reduce unnecessary CI runs

---

## 📊 Target Architecture

### Simplified Workflow Structure:

```
PR Opened/Updated:
├── go.yml (Go linting + unit tests)
├── ci.yml (Integration tests - Linux + Windows)
├── zizmor.yml (Security scan)
└── dependency-review.yml (Dependency scanning)

Push to Main:
├── build.yml (GoReleaser validation)
├── github-oidc-test.yml (GitHub provider test)
├── cli-docs.yml (Auto-generate docs)
├── coverage.yml (Coverage reporting)
└── release-drafter.yml (Draft release notes)

Tag Published (v*):
├── release.yml (Unified GoReleaser for ALL platforms)
└── validate-release.yml (Smoke test releases)
```

---

## Expected Benefits

### Performance
- **25-30% faster CI** through parallel execution and caching
- **Reduced duplicate work** by consolidating test runs
- **Shorter feedback loops** for developers

### Reliability
- **Better Windows support** with dedicated testing
- **Catch platform-specific bugs** earlier
- **Validated releases** before users download

### Security
- **Automated dependency scanning**
- **Proactive vulnerability detection**
- **Security-first workflow design**

### Maintainability
- **Clear workflow responsibilities**
- **Reduced duplication**
- **Better documentation**
- **Easier to understand and modify**

---

## Implementation Notes

### Windows Testing Considerations
- Docker-based Linux integration tests won't work on Windows
- Need separate test strategy for Windows
- Consider using Windows-native OpenSSH for testing
- May need Windows-specific test fixtures

### GoReleaser Configuration
- Ensure PowerShell scripts included in Windows releases
- Verify checksums generation for all artifacts
- Test GoReleaser locally before deploying

### Breaking Changes
- None expected - purely internal CI improvements
- Release artifacts should remain compatible

---

## Success Metrics

- ✅ All tests pass on Windows
- ✅ Windows ARM64 binaries available in releases
- ✅ CI execution time reduced by >20%
- ✅ Zero duplicate workflows
- ✅ 100% workflow documentation coverage
- ✅ All security scans passing

---

## Timeline Estimate

- **Phase 1** (Windows Support): 1-2 days
- **Phase 2** (Testing Optimization): 1 day
- **Phase 3** (Security): 1 day
- **Phase 4** (Release Validation): 1 day
- **Phase 5** (Documentation): 0.5 days
- **Phase 6** (Performance): 1 day

**Total Estimated Effort**: 5.5-6.5 days

---

_Document created: February 3, 2026_
_Last updated: February 3, 2026_
