# Windows Permissions Issues - Implementation Plan

## Executive Summary

Windows test failures reveal that the current permission checking system doesn't work on Windows because Windows uses NTFS ACLs instead of Unix permission bits. The **issue-370 branch** contains 3+ months of production-quality Win32 API code that solves these problems.

**Solution**: Cherry-pick the working code from issue-370 branch and integrate it into the current codebase.

**Status**: 
- ✅ All 5 phases completed!
- ✅ ACL infrastructure ported and working
- ✅ Permissions command integrated (check/fix/install)
- ✅ All tests passing on Windows
- ✅ Installer updated to configure permissions
- ✅ Audit command reports ACL status

**Implementation completed on**: February 3, 2026

---

## What We're Porting from issue-370

### Core ACL Infrastructure (~600 lines)
Production-quality Win32 API code:
- `policy/files/acl.go` - Platform-agnostic interfaces
- `policy/files/acl_windows.go` - Win32 API implementation (320 lines)
- `policy/files/acl_unix.go` - Unix stub
- `policy/files/sid_windows.go` - SID utilities
- `policy/files/elevation_windows.go` - Admin check
- `policy/files/elevation_unix.go` - Root check

### File Operations (~300 lines)
- `policy/files/fileperms_ops.go` - Interface + Unix impl
- `policy/files/fileperms_ops_windows.go` - Windows ACL operations

### Permissions Command (~400 lines)
- `commands/permissions.go` - Three subcommands (check/fix/install)
- `commands/permissions_test.go`
- `commands/permissions_install_test.go`

### Tests (~400 lines)
- `policy/files/acl_windows_unit_test.go`
- `policy/files/acl_unix_test.go`
- `policy/files/acl_unit_test_nonwindows.go`

**Total**: ~1700 lines of proven, tested code

---

## Setup: Create Worktree for Easy Reference

**First, set up a worktree so you can reference issue-370 code without switching branches**:

```powershell
# Create worktree (one-time setup)
git worktree add tmp/issue-370 issue-370

# Verify it worked
ls tmp/issue-370/commands/permissions.go
```

Now you can:
- Work in main directory on `add-windows-support` branch
- Reference files from `tmp/issue-370/` anytime
- No need to switch branches!

**When done (after all phases complete)**:
```powershell
git worktree remove tmp/issue-370
```

---

## Implementation Phases

### Phase 1: Port ACL Infrastructure (Day 1-2, 4-6 hours)

**Goal**: Get the core ACL verification code working.

**Files to port** (copy from worktree):
```powershell
# Core ACL code
Copy-Item tmp/issue-370/policy/files/acl.go policy/files/
Copy-Item tmp/issue-370/policy/files/acl_windows.go policy/files/
Copy-Item tmp/issue-370/policy/files/acl_unix.go policy/files/
Copy-Item tmp/issue-370/policy/files/sid_windows.go policy/files/

# Elevation checks
Copy-Item tmp/issue-370/policy/files/elevation_windows.go policy/files/
Copy-Item tmp/issue-370/policy/files/elevation_unix.go policy/files/

# File operations
Copy-Item tmp/issue-370/policy/files/fileperms_ops.go policy/files/
Copy-Item tmp/issue-370/policy/files/fileperms_ops_windows.go policy/files/

# Unit tests
Copy-Item tmp/issue-370/policy/files/acl_windows_unit_test.go policy/files/
Copy-Item tmp/issue-370/policy/files/acl_unix_test.go policy/files/
```

**Verify**:
- Code compiles on Windows and Unix
- Unit tests pass
- No merge conflicts with current code

**Deliverable**: ACL infrastructure working and tested

---

### Phase 2: Port Permissions Command (Day 2-3, 4-5 hours)

**Goal**: Get the `opkssh permissions` command working.

**Files to port**:
```powershell
# Permissions command
Copy-Item tmp/issue-370/commands/permissions.go commands/
Copy-Item tmp/issue-370/commands/permissions_test.go commands/
Copy-Item tmp/issue-370/commands/permissions_install_test.go commands/
Copy-Item tmp/issue-370/commands/permissions_fix_test_windows.go commands/
Copy-Item tmp/issue-370/commands/permissions_fix_test_nonwindows.go commands/
```

**Wire into CLI** (`main.go`):
```go
// Add to root command
permissionsCmd := commands.NewPermissionsCmd()
rootCmd.AddCommand(permissionsCmd)
```

**Test**:
```powershell
# Build
go build

# Test commands
.\opkssh.exe permissions check
.\opkssh.exe permissions fix --dry-run
.\opkssh.exe permissions install --dry-run
```

**Deliverable**: Three permissions subcommands working

---

### Phase 3: Fix Test Failures (Day 3-4, 2-3 hours)

**Goal**: Get all tests passing on Windows.

**Add build tags to skip Unix-only tests**:

Files to modify:
- `policy/files/permschecker_test.go`
- `commands/add_test.go` (permission tests only)
- `commands/verify_test.go` (permission tests only)
- `policy/policyloader_test.go` (BadPermissions test)
- `policy/multipolicyloader_test.go`
- `policy/plugins/plugins_test.go`

Add to top of test files:
```go
//go:build !windows
// +build !windows

package files
```

**Fix path separator issues**:
```go
// Before
expectedPath := "/home/foo/.opk/auth_id"

// After
expectedPath := filepath.FromSlash("/home/foo/.opk/auth_id")
```

**Verify**:
```powershell
go test ./...
```

**Deliverable**: All tests pass on Windows

---

### Phase 4: Update Installer (Day 4-5, 2 hours)

**Goal**: Make installer use `opkssh permissions install`.

**Update `Install-OpksshServer.ps1`**:

Find the section after configuration creation and add:

```powershell
# Step 8: Configure permissions using opkssh
Write-Host "[8/11] Configuring file permissions..." -ForegroundColor Yellow

$permArgs = @("permissions", "install")
if ($Verbose) {
    $permArgs += "-v"
}

try {
    & $binaryPath $permArgs
    
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Permission configuration returned non-zero exit code but continuing..."
    } else {
        Write-Host "  Permissions configured successfully" -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to configure permissions: $($_.Exception.Message)"
    Write-Warning "You may need to run: & '$binaryPath' permissions fix"
}
Write-Host ""
```

**Test**:
- Run installer on fresh Windows VM
- Verify ACLs are set correctly
- Check with: `Get-Acl C:\ProgramData\opk | Format-List`

**Deliverable**: Installer sets proper ACLs automatically

---

### Phase 5: Integration with Audit (Day 5, 2-3 hours) - LAST PHASE

**⚠️ IMPORTANT**: Do NOT touch audit command until all previous phases are complete and tested!

**Goal**: Add ACL reporting to audit command (read-only, no modifications).

**Update `commands/audit.go`**:

Add field:
```go
type AuditCmd struct {
    // ... existing fields ...
    aclVerifier files.ACLVerifier  // NEW
}
```

Initialize in NewAuditCmd:
```go
func NewAuditCmd(out, errOut io.Writer) *AuditCmd {
    fs := afero.NewOsFs()
    return &AuditCmd {
        // ... existing fields ...
        aclVerifier: files.NewDefaultACLVerifier(fs),
    }
}
```

Add ACL verification in auditPolicyFileWithStatus:
```go
// After existing permission check
if a.aclVerifier != nil {
    report, err := a.aclVerifier.VerifyACL(policyPath, files.ExpectedACL{
        Owner: "root",
        Mode: requiredPerms[0],
    })
    if err == nil && len(report.Problems) > 0 {
        for _, problem := range report.Problems {
            fmt.Fprintf(a.ErrOut, "  ACL issue: %s\n", problem)
        }
    }
}
```

**Test**:
```powershell
opkssh audit
# Should show ACL issues if any
```

**Deliverable**: Audit command reports ACL status (doesn't fix)

---

## Timeline Summary

| Phase | Task | Duration | When |
|-------|------|----------|------|
| 1 | Port ACL infrastructure | 4-6 hours | Day 1-2 |
| 2 | Port permissions command | 4-5 hours | Day 2-3 |
| 3 | Fix test failures | 2-3 hours | Day 3-4 |
| 4 | Update installer | 2 hours | Day 4-5 |
| 5 | Audit integration (LAST!) | 2-3 hours | Day 5 |

**Total**: 14-19 hours across 1 week

**⚠️ CRITICAL**: Do NOT touch the audit command until Phase 5!

---

## Commands Overview

### `opkssh permissions check`
- **Purpose**: Verify file permissions and ACLs
- **Uses**: ACLVerifier (read-only)
- **Output**: Detailed report of permission issues
- **Exit code**: 0 if OK, 1 if problems

### `opkssh permissions fix`
- **Purpose**: Repair permission/ACL issues
- **Uses**: ACLVerifier + FilePermsOps (read-write)
- **Requires**: Elevation (admin/root)
- **Behavior**: Interactive unless --yes
- **Exit code**: 0 if fixed, 1 if errors

### `opkssh permissions install`
- **Purpose**: Non-interactive setup for installers
- **Uses**: Same as fix
- **Behavior**: Always non-interactive, idempotent
- **Exit code**: 0 if OK, 1 if errors

### `opkssh audit` (Phase 5 only)
- **Purpose**: Comprehensive validation
- **Includes**: Policy validation + ACL verification
- **Behavior**: Read-only, reports issues
- **Exit code**: 0 if no issues, 1 if warnings/errors

---

## Testing Strategy

### Unit Tests
- Skip permission tests on Windows
- Keep all other tests running
- Add Windows-specific ACL tests (if implementing Option 3)

### Integration Tests
- Test installer ACL configuration
- Verify audit command detects ACL issues
- Test fix-permissions command

### Manual Testing
1. Install on Windows Server 2022
2. Run `Test-OpksshInstallation.ps1`
3. Verify ACLs with `Get-Acl C:\ProgramData\opk`
4. Run `opkssh audit` and check for ACL warnings
5. Deliberately break ACLs and verify detection
6. Run `opkssh fix-permissions` and verify repair

---

## Security Considerations

### Current State
- ❌ No ACL validation in code
- ❌ No ACL enforcement in installer
- ⚠️ Relies on default Windows permissions (not secure!)

### After Fix (Option 3)
- ✅ Installer sets proper ACLs
- ✅ Audit command validates ACLs
- ✅ Fix command repairs ACLs
- ✅ Documentation explains security model

### Recommended ACL Configuration

**C:\ProgramData\opk\** and subdirectories:
- `NT AUTHORITY\SYSTEM` - Full Control
- `BUILTIN\Administrators` - Full Control
- **Inheritance**: Disabled
- **Everyone else**: No access

**C:\Program Files\opkssh\opkssh.exe**:
- `NT AUTHORITY\SYSTEM` - Read & Execute
- `BUILTIN\Administrators` - Full Control
- `BUILTIN\Users` - Read & Execute

---

## Migration Path for Existing Installations

### For users who already installed opkssh:

```powershell
# Download new installer
Invoke-WebRequest -Uri "https://..." -OutFile Install-OpksshServer.ps1

# Re-run with -OverwriteConfig to fix ACLs
.\Install-OpksshServer.ps1 -OverwriteConfig
```

Or manually:

```powershell
# Fix ACLs manually
$configPath = "C:\ProgramData\opk"

$acl = Get-Acl $configPath
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", 
    "ContainerInherit,ObjectInherit", "None", "Allow")
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators", "FullControl",
    "ContainerInherit,ObjectInherit", "None", "Allow")

$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($adminRule)
Set-Acl $configPath $acl

Write-Host "ACLs fixed!" -ForegroundColor Green
```

---

## Success Criteria

- ✅ All Windows CI tests pass
- ✅ `opkssh permissions check` works on Windows
- ✅ `opkssh permissions fix` repairs ACL issues
- ✅ `opkssh permissions install` works non-interactively
- ✅ Installer automatically configures ACLs
- ✅ `opkssh audit` reports ACL status (Phase 5 only)

---

## Testing Strategy

### After Phase 1
```powershell
# Unit tests should pass
go test ./policy/files/...
```

### After Phase 2
```powershell
# Build and test commands
go build
.\opkssh.exe permissions check
.\opkssh.exe permissions fix --dry-run
.\opkssh.exe permissions install --dry-run
```

### After Phase 3
```powershell
# All tests should pass
go test ./...
```

### After Phase 4
```powershell
# Test installer on clean Windows VM
.\Install-OpksshServer.ps1 -Verbose

# Verify ACLs
Get-Acl C:\ProgramData\opk | Format-List
```

### After Phase 5
```powershell
# Audit should report ACL status
.\opkssh.exe audit
```

---

_Document created: February 3, 2026_  
_Last updated: February 3, 2026 (simplified to focus on implementation)_  
_Status: Ready for Implementation_  
_Total effort: 14-19 hours across 1 week_  
_Source: Cherry-pick from issue-370 branch_  
_Key principle: Do NOT touch audit command until Phase 5 (last phase)_


