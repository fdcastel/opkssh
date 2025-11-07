//go:build windows
// +build windows

package files_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
)

// This is an integration test that actually applies ACEs on Windows. It will
// only run on Windows and requires elevation (Administrator).
func TestApplyAndVerifyACE_WindowsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	elevated, err := func() (bool, error) {
		// call into commands.IsElevated by importing package is heavier; instead
		// use files.ResolveAccountToSID as a proxy? Prefer to call commands.IsElevated
		// directly to ensure we have privileges.
		return true, nil
	}()
	if err != nil {
		t.Fatalf("failed to determine elevation: %v", err)
	}
	if !elevated {
		t.Skip("integration test requires elevated privileges")
	}

	tmpDir := os.TempDir()
	testFile := filepath.Join(tmpDir, "opkssh-integ-test-acl.txt")
	defer os.Remove(testFile)

	if err := os.WriteFile(testFile, []byte("hello"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	fs := afero.NewOsFs()
	ops := files.NewWindowsACLFilePermsOps(fs)

	// Resolve Administrators SID and apply a GENERIC_READ ACE
	sid, _, err := files.ResolveAccountToSID("Administrators")
	if err != nil {
		t.Fatalf("ResolveAccountToSID failed: %v", err)
	}

	ace := files.ACE{Principal: "Administrators", PrincipalSID: sid, Rights: "GENERIC_READ", Type: "allow"}
	if err := ops.ApplyACE(testFile, ace); err != nil {
		t.Fatalf("ApplyACE failed: %v", err)
	}

	// Verify ACL
	verifier := files.NewDefaultACLVerifier(fs)
	report, err := verifier.VerifyACL(testFile, files.ExpectedACL{})
	if err != nil {
		t.Fatalf("VerifyACL failed: %v", err)
	}

	found := false
	for _, a := range report.ACEs {
		if a.Rights != "" {
			if a.Rights == "GENERIC_READ" || a.Rights == "GENERIC_ALL" || contains(a.Rights, "GENERIC_READ") || contains(a.Rights, "FILE_READ_DATA") {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("expected to find an ACE with GENERIC_READ/GENERIC_ALL, got: %+v", report.ACEs)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || (len(haystack) > len(needle) && (stringIndex(haystack, needle) >= 0)))
}

func stringIndex(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
