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

package policy

import (
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestLoadPolicyAtPath_BadPermissions(t *testing.T) {
	// Test that LoadPolicyAtPath returns an error when the file has invalid
	// permission bits
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	mockFs := NewMockFsOpenError()
	policyLoader := NewTestHomePolicyLoader(
		mockFs,
		mockUserLookup,
	)
	// Create empty policy with bad permissions
	err := afero.WriteFile(mockFs, policy.SystemDefaultPolicyPath, []byte{}, 0777)
	require.NoError(t, err)

	contents, err := policyLoader.LoadPolicyAtPath(policy.SystemDefaultPolicyPath)

	require.Error(t, err, "should fail if permissions are bad")
	require.Nil(t, contents, "should not return contents if error")
}
