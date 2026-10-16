// Copyright 2026 Dominik Schlosser
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

package wallet

import (
	"crypto/ecdsa"
	"testing"
	"time"
)

func reusePolicyMetadata(option map[string]any) map[string]any {
	return map[string]any{
		"batch_credential_issuance": map[string]any{"batch_size": float64(8)},
		"credential_configurations_supported": map[string]any{
			"pid": map[string]any{
				"credential_metadata": map[string]any{
					"credential_reuse_policy": map[string]any{
						"id":      "arf_annex_ii",
						"options": []any{option},
					},
				},
			},
		},
	}
}

// ETSI TS 119 472-3 V1.1.1 ISS-MDATA-EAA-REUSE-POL-4.2.4.2-14: with a
// credential_reuse_policy the wallet ignores batch_credential_issuance. -05:
// with one method the wallet "shall behave as specified by the string". -06:
// with several it follows the first supported one.
func TestReusePolicyDecidesTheBatchSize(t *testing.T) {
	cases := []struct {
		name     string
		option   map[string]any
		wantKeys int
	}{
		{"once_only", map[string]any{"details": []any{"once_only"}, "batch_size": float64(4), "reissue_trigger_unused": float64(2)}, 4},
		{"limited_time", map[string]any{"details": []any{"limited_time"}, "reissue_trigger_lifetime_left": float64(86400)}, 1},
		{"limited-time", map[string]any{"details": []any{"limited-time"}, "reissue_trigger_lifetime_left": float64(86400)}, 1},
		{"first supported method", map[string]any{"details": []any{"per-relying-party", "rotating-batch"}, "batch_size": float64(3), "reissue_trigger_lifetime_left": float64(86400)}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			w.RequireARF = true
			metadata := reusePolicyMetadata(tc.option)
			keys, err := issuanceProofKeys(metadata, w.reuseOption(metadata, "pid"))
			if err != nil {
				t.Fatalf("issuanceProofKeys: %v", err)
			}
			if len(keys) != tc.wantKeys {
				t.Errorf("requested %d copies, want %d", len(keys), tc.wantKeys)
			}
		})
	}
}

// ARF ISSU_39a is an ARF rule, so without --arf the wallet follows
// batch_credential_issuance (OpenID4VCI 1.0 §12.2.4).
func TestReusePolicyNeedsARF(t *testing.T) {
	w := generateTestWallet(t)
	metadata := reusePolicyMetadata(map[string]any{"details": []any{"once_only"}, "batch_size": float64(4), "reissue_trigger_unused": float64(2)})
	if reuse := w.reuseOption(metadata, "pid"); reuse != nil {
		t.Fatalf("reuse option without --arf = %+v, want none", reuse)
	}
}

// ARF ISSU_45: under once_only the wallet requests a new batch when the
// unused copies reach reissue_trigger_unused (472-3 -10).
func TestOnceOnlyRenewsAtTheUnusedLimit(t *testing.T) {
	w := generateTestWallet(t)
	keys := []*ecdsa.PrivateKey{testKey(t), testKey(t), testKey(t), testKey(t)}
	storeTestBatch(t, w, keys)
	creds := w.GetCredentials()
	primary := creds[0]
	primary.Renewal = &CredentialRenewal{ReusePolicy: &ReuseOption{Method: reuseOnceOnly, BatchSize: 4, ReissueTriggerUnused: 2}}

	now := time.Now()
	w.recordBatchPresentation(creds[1].ID)
	if w.credentialNeedsRenewal(primary, now) {
		t.Fatal("renewal with 3 unused copies, want it at 2")
	}
	w.recordBatchPresentation(creds[2].ID)
	if !w.credentialNeedsRenewal(primary, now) {
		t.Fatal("no renewal with 2 unused copies and a limit of 2")
	}
}

// 472-3 -13: reissue_trigger_lifetime_left is "the number of seconds before
// the expiration of the PID/EAA" at which the wallet renews.
func TestReusePolicyRenewsAtTheLifetimeLeft(t *testing.T) {
	w := generateTestWallet(t)
	cred := StoredCredential{
		Format:  "dc+sd-jwt",
		Raw:     sdJWTBoundTo(t, w, &w.HolderKey.PublicKey),
		Renewal: &CredentialRenewal{ReusePolicy: &ReuseOption{Method: reuseLimitedTime, ReissueTriggerLifetimeLeft: 2 * 86400}},
	}
	// sdJWTBoundTo issues for a day, inside the two days of the policy.
	if !w.credentialNeedsRenewal(cred, time.Now()) {
		t.Error("no renewal inside reissue_trigger_lifetime_left")
	}
	cred.Renewal.ReusePolicy.ReissueTriggerLifetimeLeft = 3600
	if w.credentialNeedsRenewal(cred, time.Now()) {
		t.Error("renewal a day before expiry with a trigger of an hour")
	}
}
