//go:build windows
// +build windows

package files

import (
	"fmt"
	"github.com/spf13/afero"
)

// WindowsACLVerifier is a stub for Windows implementation which will be
// implemented with Win32 APIs in a follow-up. For now it reports existence
// and returns a problem indicating verification not implemented.
type WindowsACLVerifier struct {
	Fs afero.Fs
}

func NewDefaultACLVerifier(fs afero.Fs) ACLVerifier {
	return &WindowsACLVerifier{Fs: fs}
}

func (w *WindowsACLVerifier) VerifyACL(path string, expected ExpectedACL) (ACLReport, error) {
	r := ACLReport{Path: path}
	if w.Fs == nil {
		w.Fs = afero.NewOsFs()
	}
	if _, err := w.Fs.Stat(path); err != nil {
		r.Exists = false
		r.Problems = append(r.Problems, fmt.Sprintf("open %s: %v", path, err))
		return r, nil
	}
	r.Exists = true
	r.Problems = append(r.Problems, "Windows ACL verification is not yet implemented using Win32 APIs; add ACL verifier to check owner and ACEs")
	return r, nil
}
