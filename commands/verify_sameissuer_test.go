// Copyright 2026 OpenPubkey
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
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/openpubkey/opkssh/sshcert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestAuthorizedKeysCommand_SameIssuerTwoClientIDs checks a server whose
// providers file has two rows for one issuer with different client IDs, e.g.
// while migrating from one Google OAuth client to another:
//
//	https://accounts.google.com client-a oidc
//	https://accounts.google.com client-b 12h
//
// As with Google, both rows trust the same signing keys and differ only in the
// audience they accept, so only the aud check tells the tokens apart.
func TestAuthorizedKeysCommand_SameIssuerTwoClientIDs(t *testing.T) {
	t.Parallel()
	const issuer = "https://accounts.google.com"

	// The mock OP mints tokens for any audience; the rows below enforce it.
	op, backend, idtTemplate, err := providers.NewMockProvider(providers.MockProviderOpts{
		Issuer:     issuer,
		ClientID:   "client-a",
		NumKeys:    2,
		CommitType: providers.CommitTypesEnum.NONCE_CLAIM,
		VerifierOpts: providers.ProviderVerifierOpts{
			CommitType:        providers.CommitTypesEnum.NONCE_CLAIM,
			SkipClientIDCheck: true,
		},
	})
	require.NoError(t, err)

	row := func(clientID string, expiration verifier.ExpirationPolicy) verifier.ProviderVerifier {
		return verifier.ProviderVerifierExpires{
			ProviderVerifier: providers.NewProviderVerifier(issuer, providers.ProviderVerifierOpts{
				CommitType:        providers.CommitTypesEnum.NONCE_CLAIM,
				ClientID:          clientID,
				DiscoverPublicKey: &backend.PublicKeyFinder,
			}),
			Expiration: expiration,
		}
	}
	rowA := row("client-a", verifier.ExpirationPolicies.NEVER_EXPIRE)
	rowB := row("client-b", verifier.ExpirationPolicies.MAX_AGE_12HOURS)

	thirteenHoursAgo := time.Now().Add(-13 * time.Hour).Unix()

	tests := []struct {
		name        string
		aud         string
		iat         int64
		errorString string
	}{
		{name: "token for first client ID", aud: "client-a"},
		{name: "token for second client ID", aud: "client-b"},
		{name: "token for unknown client ID", aud: "client-c", errorString: "rejected by all 2 provider verifiers"},
		{name: "old token, row with no max age", aud: "client-a", iat: thirteenHoursAgo},
		{name: "old token, row with 12h max age", aud: "client-b", iat: thirteenHoursAgo, errorString: "expired"},
	}

	orders := map[string][]verifier.ProviderVerifier{
		"A then B": {rowA, rowB},
		"B then A": {rowB, rowA},
	}

	for orderName, rows := range orders {
		for _, tt := range tests {
			t.Run(orderName+"/"+tt.name, func(t *testing.T) {
				alg := jose.ES256
				signer, err := util.GenKeyPair(alg)
				require.NoError(t, err)

				idtTemplate.Aud = tt.aud
				idtTemplate.ExtraClaims = map[string]any{"email": "alice@example.com"}
				if tt.iat != 0 {
					idtTemplate.ExtraClaims["iat"] = tt.iat
				}
				c, err := client.New(op, client.WithSigner(signer, alg))
				require.NoError(t, err)
				pkt, err := c.Auth(context.Background())
				require.NoError(t, err)

				cert, err := sshcert.New(pkt, nil, []string{"guest"})
				require.NoError(t, err)
				sshSigner, err := ssh.NewSignerFromSigner(signer)
				require.NoError(t, err)
				signerMas, err := ssh.NewSignerWithAlgorithms(sshSigner.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoECDSA256})
				require.NoError(t, err)
				sshCert, err := cert.SignCert(signerMas)
				require.NoError(t, err)
				typeAndCert := strings.Split(string(ssh.MarshalAuthorizedKey(sshCert)), " ")

				pktVerifier, err := verifier.NewFromMany(rows)
				require.NoError(t, err)
				ver := VerifyCmd{
					PktVerifier: *pktVerifier,
					CheckPolicy: AllowAllPolicyEnforcer,
				}

				pubkeyList, err := ver.AuthorizedKeysCommand(context.Background(), "guest", typeAndCert[0], typeAndCert[1], nil)
				if tt.errorString != "" {
					require.ErrorContains(t, err, tt.errorString)
					require.Empty(t, pubkeyList)
				} else {
					require.NoError(t, err)
					require.Contains(t, pubkeyList, `cert-authority,principals="guest"`)
				}
			})
		}
	}
}
