/*
Copyright 2026 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"k8s.io/client-go/rest"

	"hegel.dev/go/hegel"

	"github.com/cert-manager/csi-lib/metadata"
)

type tokenEntry struct {
	Token  string `json:"token"`
	Expiry string `json:"expiry,omitempty"`
}

// drawTokens draws a kubelet-style audience→token map (as kubelet serializes
// into the csi.storage.k8s.io/serviceAccount.tokens volume context key) and
// returns it with the empty-audience token ("" if absent or empty).
func drawTokens(ht *hegel.T) (map[string]tokenEntry, string) {
	tokens := map[string]tokenEntry{}
	emptyAudToken := ""
	if hegel.Draw(ht, hegel.Booleans()) {
		emptyAudToken = hegel.Draw(ht, hegel.Text().MaxSize(20))
		tokens[""] = tokenEntry{Token: emptyAudToken, Expiry: "Wed, 11 Aug 2021 09:03:03 GMT"}
	}
	audiences := []string{"vault", "kubernetes.io", "aud-x"}
	for _, i := range hegel.Draw(ht, hegel.Lists(hegel.Integers(0, int64(len(audiences)-1))).MaxSize(3)) {
		tokens[audiences[i]] = tokenEntry{Token: hegel.Draw(ht, hegel.Text().MaxSize(20))}
	}
	return tokens, emptyAudToken
}

// TestRestConfigForMetadataTokenRequestEmptyAudProperty: the returned getter
// succeeds iff the volume context carries the kubelet token-request key with
// a non-empty token for the empty ("") audience. On success the rest config
// is exactly the seed's Host, TLSClientConfig, UserAgent and Timeout with the
// empty-audience token as the bearer token — in particular the seed's own
// BearerToken must never leak into the per-volume config. Replaces the
// Test_restConfigForMetadataTokenRequestEmptyAud table, whose five rows were
// instances of this rule.
func TestRestConfigForMetadataTokenRequestEmptyAudProperty(t *testing.T) {
	baseRestConfig := &rest.Config{
		Host:            "my-host",
		TLSClientConfig: rest.TLSClientConfig{ServerName: "my-server"},
		BearerToken:     "driver-own-token",
		UserAgent:       "csi.cert-manager.io/unit-tests",
		Timeout:         time.Millisecond,
	}
	getter := restConfigForMetadataTokenRequestEmptyAud(baseRestConfig)

	hegel.Test(t, func(ht *hegel.T) {
		volumeContext := map[string]string{}
		wantToken := ""
		if hegel.Draw(ht, hegel.Booleans()) {
			tokens, emptyAudToken := drawTokens(ht)
			wantToken = emptyAudToken
			tokensJSON, err := json.Marshal(tokens)
			if err != nil {
				ht.Fatalf("marshaling tokens: %v", err)
			}
			volumeContext[metadata.SATokenVolumeContextKey] = string(tokensJSON)
		}

		restConfig, err := getter(metadata.Metadata{VolumeContext: volumeContext})

		if wantToken == "" {
			if err == nil {
				ht.Fatalf("volume context %v: want error, got config %v", volumeContext, restConfig)
			}
			return
		}
		if err != nil {
			ht.Fatalf("volume context %v: unexpected error: %v", volumeContext, err)
		}
		want := &rest.Config{
			Host:            "my-host",
			TLSClientConfig: rest.TLSClientConfig{ServerName: "my-server"},
			UserAgent:       "csi.cert-manager.io/unit-tests",
			Timeout:         time.Millisecond,
			BearerToken:     wantToken,
		}
		if !reflect.DeepEqual(want, restConfig) {
			ht.Fatalf("want rest config %v, got %v", want, restConfig)
		}
	}, hegel.WithTestCases(1000))
}

// TestEmptyAudienceTokenFromMetadata_arbitraryText: arbitrary (non-JSON)
// values under the token-request key must produce an error, never a panic
// and never an empty token with a nil error.
func TestEmptyAudienceTokenFromMetadata_arbitraryText(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		meta := metadata.Metadata{VolumeContext: map[string]string{
			metadata.SATokenVolumeContextKey: hegel.Draw(ht, hegel.Text().MaxSize(40)),
		}}
		token, err := EmptyAudienceTokenFromMetadata(meta)
		if err == nil && token == "" {
			ht.Fatalf("returned empty token without error")
		}
	}, hegel.WithTestCases(1000))
}
