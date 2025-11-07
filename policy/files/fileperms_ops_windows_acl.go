//go:build windows
// +build windows

package files

import (
	"fmt"
	"io/fs"
	"os/exec"
	"strings"

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
