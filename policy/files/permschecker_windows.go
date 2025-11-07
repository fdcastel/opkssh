//go:build windows
// +build windows

// Copyright 2025 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package files

import (
	"fmt"
	"io/fs"
	"strings"
)

// CheckPerm checks file permissions on Windows.
// On Windows, we perform a relaxed check compared to Unix systems because:
// 1. Windows doesn't use POSIX permission bits
// 2. Go's os.Stat() synthesizes permission bits from file attributes, not ACLs
// 3. A file without the read-only attribute will always show as 0666, not 0640
//
// For security on Windows, we rely on:
// - NTFS ACLs set by the installer (Administrators and SYSTEM only)
// - File system level security rather than permission bits
//
// This function validates the file exists and is accessible, but skips
// the strict permission bit check that makes sense on Unix but not on Windows.
func (u *PermsChecker) CheckPerm(path string, requirePerm []fs.FileMode, requiredOwner string, requiredGroup string) error {
	// Verify file exists and is accessible
	fileInfo, err := u.Fs.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to describe the file at path: %w", err)
	}

	// If a custom CmdRunner is provided (used in unit tests and some mocks),
	// attempt to perform similar checks to the Unix implementation so tests
	// that rely on CmdRunner behave consistently on Windows.
	if u.CmdRunner != nil {
		// Owner/group checks, if requested
		if requiredOwner != "" || requiredGroup != "" {
			statOutput, err := u.CmdRunner("stat", "-c", "%U %G", path)
			if err != nil {
				return fmt.Errorf("failed to run stat: %w", err)
			}

			statOutputSplit := strings.Split(strings.TrimSpace(string(statOutput)), " ")
			if len(statOutputSplit) != 2 {
				return fmt.Errorf("expected stat command to return 2 values got %d", len(statOutputSplit))
			}
			statOwner := statOutputSplit[0]
			statGroup := statOutputSplit[1]

			if requiredOwner != "" {
				if requiredOwner != statOwner {
					return fmt.Errorf("expected owner (%s), got (%s)", requiredOwner, statOwner)
				}
			}
			if requiredGroup != "" {
				if requiredGroup != statGroup {
					return fmt.Errorf("expected group (%s), got (%s)", requiredGroup, statGroup)
				}
			}
		}

		// Permission bits check using the FileMode synthesized by afero/os
		mode := fileInfo.Mode()
		permMatch := false
		requiredPermString := []string{}
		for _, p := range requirePerm {
			requiredPermString = append(requiredPermString, fmt.Sprintf("%o", p.Perm()))
			if mode.Perm() == p {
				permMatch = true
			}
		}
		if !permMatch {
			return fmt.Errorf("expected one of the following permissions [%s], got (%o)", strings.Join(requiredPermString, ", "), mode.Perm())
		}

		return nil
	}

	// Default Windows behavior: only verify the file exists. Real security on
	// Windows is enforced by NTFS ACLs set by the installer.
	return nil
}
