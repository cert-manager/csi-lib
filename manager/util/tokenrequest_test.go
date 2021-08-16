/*
Copyright 2021 The cert-manager Authors.

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
	"testing"
	"time"

	"k8s.io/client-go/rest"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/stretchr/testify/assert"
)

func Test_restConfigForMetadataTokenRequestEmptyAud(t *testing.T) {
	var (
		baseRestConfig = &rest.Config{
			Host: "my-host",
			TLSClientConfig: rest.TLSClientConfig{
				ServerName: "my-server",
			},
			BearerToken: "my-token",
			UserAgent:   "csi.cert-manager.io/unit-tests",
			Timeout:     time.Millisecond,
		}
	)

	tests := map[string]struct {
		volumeContext map[string]string
		expRestConfig *rest.Config
		expErr        bool
	}{
		"volume context doesn't contain any token requests should error": {
			volumeContext: map[string]string{},
			expRestConfig: nil,
			expErr:        true,
		},
		"volume context contains token request entry but json is garbage should error": {
			volumeContext: map[string]string{
				"csi.storage.k8s.io/serviceAccount.tokens": "garbage-data",
			},
			expRestConfig: nil,
			expErr:        true,
		},
		"volume context contains token requests, but not an empty audience should error": {
			volumeContext: map[string]string{
				"csi.storage.k8s.io/serviceAccount.tokens": `
		{
		  "vault": {
		    "token": "vault-token",
		    "expiry": "Wed, 11 Aug 2021 09:03:03 GMT"
		  },
		  "kubernetes.io": {
		    "token": "kube-token",
		    "expiry": "Wed, 11 Aug 2021 09:03:03 GMT"
			}
		}
		`,
			},
			expRestConfig: nil,
			expErr:        true,
		},
		"volume context contains only an empty audience token should return a rest config with token": {
			volumeContext: map[string]string{
				"csi.storage.k8s.io/serviceAccount.tokens": `
		{
		  "": {
		    "token": "empty-aud-token",
		    "expiry": "Wed, 11 Aug 2021 09:03:03 GMT"
			}
		}
		`,
			},
			expRestConfig: &rest.Config{
				Host: "my-host",
				TLSClientConfig: rest.TLSClientConfig{
					ServerName: "my-server",
				},
				UserAgent:   "csi.cert-manager.io/unit-tests",
				Timeout:     time.Millisecond,
				BearerToken: "empty-aud-token",
			},
			expErr: false,
		},
		"volume context contains multiple request tokens including the empty audience should return a rest config with empty audience token": {
			volumeContext: map[string]string{
				"csi.storage.k8s.io/serviceAccount.tokens": `
		{
		  "vault": {
		    "token": "vault-token",
		    "expiry": "Wed, 11 Aug 2021 09:03:03 GMT"
		  },
		  "": {
		    "token": "another-empty-aud-token",
		    "expiry": "Wed, 11 Aug 2021 09:03:03 GMT"
			},
		  "kubernetes.io": {
		    "token": "kube-token",
		    "expiry": "Wed, 11 Aug 2021 09:03:03 GMT"
			}
		}
		`,
			},
			expRestConfig: &rest.Config{
				Host: "my-host",
				TLSClientConfig: rest.TLSClientConfig{
					ServerName: "my-server",
				},
				UserAgent:   "csi.cert-manager.io/unit-tests",
				Timeout:     time.Millisecond,
				BearerToken: "another-empty-aud-token",
			},
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			restConfig, gotErr := restConfigForMetadataTokenRequestEmptyAud(baseRestConfig)(metadata.Metadata{VolumeContext: test.volumeContext})
			assert.Equal(t, test.expErr, gotErr != nil, "%v", gotErr)
			assert.Equal(t, test.expRestConfig, restConfig)
		})
	}
}
