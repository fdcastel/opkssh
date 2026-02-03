//go:build !windows
// +build !windows

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

package commands

import (
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestAddErrors_UnixPermissions(t *testing.T) {
	t.Parallel()
	principal := "foo"
	userEmail := "alice@example.com"
	issuer := "gitlab"

	// Create system policy file with wrong permissions
	mockFs := afero.NewMemMapFs()
	_, err := mockFs.Create(policy.SystemDefaultPolicyPath)
	require.NoError(t, err)
	
	addCmd := MockAddCmd(mockFs)

	policyPath, err := addCmd.Run(principal, userEmail, issuer)
	require.ErrorContains(t, err, "file has insecure permissions: expected one of the following permissions [640], got (0)")
	require.Empty(t, policyPath)
}
