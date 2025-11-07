//go:build windows
// +build windows

package files

import (
	"fmt"
	"io/fs"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"github.com/spf13/afero"
)

// WindowsACLFilePermsOps implements FilePermsOps using icacls for ACL changes.
// This provides a stricter mapping of ownership/ACL semantics on Windows.
type WindowsACLFilePermsOps struct {
	Fs afero.Fs
}

// NewWindowsACLFilePermsOps returns a FilePermsOps that applies ACL changes
// using icacls. This is more suitable for production Windows installs where
// runtime verification or repair of ACLs is desired.
func NewWindowsACLFilePermsOps(fs afero.Fs) FilePermsOps {
	return &WindowsACLFilePermsOps{Fs: fs}
}

func (w *WindowsACLFilePermsOps) MkdirAllWithPerm(path string, perm fs.FileMode) error {
	return w.Fs.MkdirAll(path, perm)
}

func (w *WindowsACLFilePermsOps) CreateFileWithPerm(path string) (afero.File, error) {
	return w.Fs.Create(path)
}

func (w *WindowsACLFilePermsOps) WriteFileWithPerm(path string, data []byte, perm fs.FileMode) error {
	return afero.WriteFile(w.Fs, path, data, perm)
}

func (w *WindowsACLFilePermsOps) Chmod(path string, perm fs.FileMode) error {
	return w.Fs.Chmod(path, perm)
}

func (w *WindowsACLFilePermsOps) Stat(path string) (fs.FileInfo, error) {
	return w.Fs.Stat(path)
}

// Chown attempts to set owner and grant basic ACLs using icacls. If icacls is
// not available or the operation fails, an error is returned.
func (w *WindowsACLFilePermsOps) Chown(path string, owner string, group string) error {
	// If nothing requested, nothing to do
	if owner == "" && group == "" {
		return nil
	}

	// Map common POSIX names to Windows principals
	ownerName := owner
	if owner == "root" {
		ownerName = "Administrators"
	}

	// Set owner
	if ownerName != "" {
		cmd := exec.Command("icacls", path, "/setowner", ownerName)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to set owner via icacls: %v: %s", err, string(out))
		}
	}

	// If group provided, grant read permissions to that group
	if group != "" {
		// Use /grant to add Read permission for group; use /inheritance:r to remove inherited perms if needed.
		grant := fmt.Sprintf("%s:(R)", group)
		cmd := exec.Command("icacls", path, "/grant", grant)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to grant group permission via icacls: %v: %s", err, string(out))
		}
	}

	// Ensure Administrators and SYSTEM have full control
	adminGrant := "Administrators:F"
	systemGrant := "SYSTEM:F"
	cmd := exec.Command("icacls", path, "/grant", adminGrant, "/grant", systemGrant)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// If cmd failed but it was because grants already exist, ignore known messages; otherwise return error
		if !strings.Contains(string(out), "Successfully processed") {
			return fmt.Errorf("failed to ensure admin/system ACLs via icacls: %v: %s", err, string(out))
		}
	}

	return nil
}

// EXPLICIT_ACCESS and TRUSTEE definitions for calling SetEntriesInAclW
type _TRUSTEE struct {
	MultipleTrustee         uintptr
	MultipleTrusteeOperator uint32
	TrusteeForm             uint32
	TrusteeType             uint32
	PtstrName               *uint16
}

type _EXPLICIT_ACCESS struct {
	GrfAccessPermissions uint32
	GrfAccessMode        uint32
	GrfInheritance       uint32
	Trustee              _TRUSTEE
}

var (
	procSetEntriesInAcl      = advapi32.NewProc("SetEntriesInAclW")
	procSetNamedSecurityInfo = advapi32.NewProc("SetNamedSecurityInfoW")
)

const (
	// from Winnt.h / AccCtrl.h
	GRANT_ACCESS       = 1
	NO_INHERITANCE     = 0
	TRUSTEE_IS_NAME    = 1
	TRUSTEE_IS_UNKNOWN = 0
)

// rightsToMask converts a human-readable rights string into a Windows access mask.
func rightsToMask(rights string) uint32 {
	var m uint32
	if strings.Contains(rights, "GENERIC_ALL") {
		m |= 0x10000000
	}
	if strings.Contains(rights, "GENERIC_READ") {
		m |= 0x80000000
	}
	if strings.Contains(rights, "GENERIC_WRITE") {
		m |= 0x40000000
	}
	if strings.Contains(rights, "FILE_READ_DATA") {
		m |= 0x00000001
	}
	if strings.Contains(rights, "FILE_WRITE_DATA") {
		m |= 0x00000002
	}
	if strings.Contains(rights, "FILE_APPEND_DATA") {
		m |= 0x00000004
	}
	if strings.Contains(rights, "FILE_EXECUTE") {
		m |= 0x00000020
	}
	if strings.Contains(rights, "READ_CONTROL") {
		m |= 0x00020000
	}
	if strings.Contains(rights, "WRITE_DAC") {
		m |= 0x00040000
	}
	if strings.Contains(rights, "WRITE_OWNER") {
		m |= 0x00080000
	}
	return m
}

// ApplyACE via Win32 APIs (SetEntriesInAclW + SetNamedSecurityInfoW)
func (w *WindowsACLFilePermsOps) ApplyACE(path string, ace ACE) error {
	// Currently only supports adding simple allow/deny entries by account name
	pPath, _ := syscall.UTF16PtrFromString(path)

	// Get existing DACL
	var pDacl uintptr
	var pSD uintptr
	ret, _, _ := procGetNamedSecInfo.Call(
		uintptr(unsafe.Pointer(pPath)),
		uintptr(SE_FILE_OBJECT),
		uintptr(DACL_SECURITY_INFORMATION),
		0,
		0,
		uintptr(unsafe.Pointer(&pDacl)),
		0,
		uintptr(unsafe.Pointer(&pSD)),
	)
	if ret != 0 {
		return fmt.Errorf("GetNamedSecurityInfoW failed: %d", ret)
	}
	if pSD != 0 {
		defer procLocalFree.Call(pSD)
	}

	// Build EXPLICIT_ACCESS
	var ea _EXPLICIT_ACCESS
	ea.GrfAccessPermissions = rightsToMask(ace.Rights)
	if ace.Type == "allow" {
		ea.GrfAccessMode = GRANT_ACCESS
	} else {
		// For deny use DENY_ACCESS(3) per ACCESS_MODE, but SetEntriesInAcl supports DENY_ACCESS as 3
		ea.GrfAccessMode = 3
	}
	ea.GrfInheritance = NO_INHERITANCE

	namePtr, _ := syscall.UTF16PtrFromString(ace.Principal)
	ea.Trustee = _TRUSTEE{
		MultipleTrustee:         0,
		MultipleTrusteeOperator: 0,
		TrusteeForm:             TRUSTEE_IS_NAME,
		TrusteeType:             TRUSTEE_IS_UNKNOWN,
		PtstrName:               namePtr,
	}

	// Call SetEntriesInAclW
	var pNewAcl uintptr
	ret2, _, err := procSetEntriesInAcl.Call(
		uintptr(1),
		uintptr(unsafe.Pointer(&ea)),
		uintptr(pDacl),
		uintptr(unsafe.Pointer(&pNewAcl)),
	)
	if ret2 != 0 {
		return fmt.Errorf("SetEntriesInAclW failed: %v (ret=%d)", err, ret2)
	}
	if pNewAcl == 0 {
		return fmt.Errorf("SetEntriesInAclW returned nil ACL")
	}
	defer procLocalFree.Call(pNewAcl)

	// Apply new DACL to the file
	ret3, _, err := procSetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(pPath)),
		uintptr(SE_FILE_OBJECT),
		uintptr(DACL_SECURITY_INFORMATION),
		0,
		0,
		uintptr(unsafe.Pointer(pNewAcl)),
		0,
	)
	if ret3 != 0 {
		return fmt.Errorf("SetNamedSecurityInfoW failed: %v (ret=%d)", err, ret3)
	}

	return nil
}
