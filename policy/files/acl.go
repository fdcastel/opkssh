package files

import (
	"io/fs"
)

// ACE represents an access control entry (platform-agnostic minimal view)
type ACE struct {
	Principal string
	Rights    string
	Type      string // Allow or Deny
	Inherited bool
}

// ExpectedACL contains the expectations for a path's ownership/ACL
type ExpectedACL struct {
	Owner string
	Mode  fs.FileMode // expected mode bits; 0 means ignore
}

// ACLReport is the structured result from verifying ACLs/ownership for a path
type ACLReport struct {
	Path     string
	Exists   bool
	Owner    string
	Mode     fs.FileMode
	ACEs     []ACE
	Problems []string
}

// ACLVerifier verifies ACLs and ownership for a given path against expectations.
// Implementations are platform-specific (Unix uses syscalls; Windows uses Win32 APIs).
type ACLVerifier interface {
	VerifyACL(path string, expected ExpectedACL) (ACLReport, error)
}
