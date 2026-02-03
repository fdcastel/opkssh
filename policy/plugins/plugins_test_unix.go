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

package plugins

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// TestPolicyPluginsWithMock_UnixPermissions tests Unix-specific permission checks
func TestPolicyPluginsWithMock_UnixPermissions(t *testing.T) {
	mockCmdExecutor := func(name string, arg ...string) ([]byte, error) {
		iss, _ := os.LookupEnv("OPKSSH_PLUGIN_ISS")
		sub, _ := os.LookupEnv("OPKSSH_PLUGIN_SUB")
		aud, _ := os.LookupEnv("OPKSSH_PLUGIN_AUD")

		if name == "/usr/bin/local/opk/policy-cmd" {

			if len(arg) != 3 {
				return nil, fmt.Errorf("expected 3 arguments, got %d", len(arg))
			} else if iss == "https://example.com" && sub == "1234" && aud == "abcd" {
				// Simulate a successful policy check
				return []byte("allow"), nil
			} else {
				return []byte("deny"), nil
			}
		} else {
			return nil, fmt.Errorf("command '%s' not found", name)
		}
	}

	configWithBadPerms := []mockFile{
		{
			Name:       "bad-perms-config.yml",
			Permission: 0606,
			Content: `
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/missing-cmd"`}}

	commandWithBadPerms := []mockFile{
		{
			Name:       "bad-perms-command.yml",
			Permission: 0640,
			Content: `
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/bad-perms-policy-cmd`}}

	tests := []struct {
		name                string
		tokens              map[string]string
		files               []mockFile
		cmdExecutor         func(name string, arg ...string) ([]byte, error)
		expectedAllowed     bool
		expectedResultCount int
		expectErrorCount    int
		errorExpected       string
	}{
		{
			name: "Policy invalid config permissions",
			tokens: map[string]string{
				"OPKSSH_PLUGIN_ISS": "https://example.com",
				"OPKSSH_PLUGIN_SUB": "1234",
				"OPKSSH_PLUGIN_AUD": "abcd",
			},
			files:               configWithBadPerms,
			cmdExecutor:         mockCmdExecutor,
			expectedAllowed:     false,
			expectedResultCount: 1,
			expectErrorCount:    1,
			errorExpected:       "expected one of the following permissions [640], got (606)",
		},
		{
			name: "Policy invalid command permissions",
			tokens: map[string]string{
				"OPKSSH_PLUGIN_ISS": "https://example.com",
				"OPKSSH_PLUGIN_SUB": "1234",
				"OPKSSH_PLUGIN_AUD": "abcd",
			},
			files:               commandWithBadPerms,
			cmdExecutor:         mockCmdExecutor,
			expectedAllowed:     false,
			expectedResultCount: 1,
			expectErrorCount:    1,
			errorExpected:       "expected one of the following permissions [555, 755], got (766)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Ensure we flush all OPKSSH_PLUGIN_ env vars before and after the test.
			for _, envVar := range os.Environ() {
				if strings.HasPrefix(envVar, "OPKSSH_PLUGIN_") {
					envVarName := strings.Split(envVar, "=")[0]
					_ = os.Unsetenv(envVarName)
					defer func(key string) {
						_ = os.Unsetenv(key)
					}(envVarName)
				}
			}

			mockFs := afero.NewMemMapFs()

			for _, file := range tt.files {
				_ = afero.WriteFile(mockFs, "/usr/bin/local/opk/"+file.Name, []byte(file.Content), file.Permission)
			}

			// Write the executable files with the specified permissions
			_ = afero.WriteFile(mockFs, "/usr/bin/local/opk/policy-cmd", []byte("#!/bin/bash\necho allow"), 0755)
			_ = afero.WriteFile(mockFs, "/usr/bin/local/opk/bad-perms-policy-cmd", []byte("#!/bin/bash\necho allow"), 0766)

			for k, v := range tt.tokens {
				_ = os.Setenv(k, v)
			}

			results := LoadPluginPolicies(mockFs, "/usr/bin/local/opk", tt.cmdExecutor)

			require.Equal(t, tt.expectedResultCount, len(results))
			actualErrorCount := 0
			for _, result := range results {
				if result.Error != nil {
					actualErrorCount++
					require.ErrorContains(t, result.Error, tt.errorExpected)
				}
			}
			require.Equal(t, tt.expectErrorCount, actualErrorCount)
		})
	}
}
