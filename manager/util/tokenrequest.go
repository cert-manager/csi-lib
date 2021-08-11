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
	"encoding/json"
	"errors"
	"fmt"

	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
)

// ClientForMetadataTokenRequestEmptyAud returns a
// manager.ClientForMetadataFunc that returns a cert-manager rest client whose
// authentication is built using the passed empty audience ("") token request
// in the metadata VolumeContext. The resulting cert-manager client is
// authenticated against the Kubernetes API server using the mounting Pod's
// ServiceAccount.
//
// Intended to be used as a manager ClientForMetadata so that created
// CertificateRequests will have UserInfo fields of the mounting Pods
// ServiceAccount.
//
// Drivers using this function _must_ have the empty audience tokenRequest
// defined on the CSIDriver manifest definition, along with setting
// requiresRepublish to true:
//
// tokenRequests:
//   - audience: ""
//     expirationSeconds: 3600
// requiresRepublish: true
//
// restConfig must contain the Kubernetes API server Host, and a valid
// TLSClientConfig.
func ClientForMetadataTokenRequestEmptyAud(restConfig *rest.Config) manager.ClientForMetadataFunc {
	restConfigGetter := restConfigForMetadataTokenRequestEmptyAud(restConfig)
	return func(meta metadata.Metadata) (cmclient.Interface, error) {
		cmRestConfig, err := restConfigGetter(meta)
		if err != nil {
			return nil, err
		}
		return cmclient.NewForConfig(cmRestConfig)
	}
}

// restConfigForMetadataTokenRequestEmptyAud returns a Kubernetes rest config
// getter that returns a rest config that is authenticated using a
// ServiceAccount defined in the empty audience token request passed in the
// volume context.
// The Host, TLSClientConfig, UserAgent, Timeout, and Proxy are preserved from
// the seed rest config.
func restConfigForMetadataTokenRequestEmptyAud(restConfig *rest.Config) func(meta metadata.Metadata) (*rest.Config, error) {
	host := restConfig.Host
	tlsClientConfig := *restConfig.DeepCopy()
	userAgent := restConfig.UserAgent
	timeout := restConfig.Timeout
	proxy := restConfig.Proxy

	return func(meta metadata.Metadata) (*rest.Config, error) {
		apiToken, err := EmptyAudienceTokenFromMetadata(meta)
		if err != nil {
			return nil, err
		}

		return &rest.Config{
			Host:            host,
			TLSClientConfig: tlsClientConfig,
			UserAgent:       userAgent,
			Timeout:         timeout,
			Proxy:           proxy,
			BearerToken:     apiToken,
		}, nil
	}
}

// EmptyAudienceTokenFromMetadata returns the empty audience service account
// token from the volume attributes contained within the metadata. This token
// should be present in the token request
// `csi.storage.k8s.io/serviceAccount.tokens` key of the metadata
// VolumeContext.
// This function will only return tokens if the CSI driver has been defined
// with tokenRequests enabled with an empty ("") audience.
func EmptyAudienceTokenFromMetadata(meta metadata.Metadata) (string, error) {
	tokens := make(map[string]struct {
		Token string `json:"token"`
	})

	tokensJson, ok := meta.VolumeContext["csi.storage.k8s.io/serviceAccount.tokens"]
	if !ok {
		return "", errors.New("'csi.storage.k8s.io/serviceAccount.tokens' not present in volume context, driver likely doesn't have token requests enabled")
	}

	err := json.Unmarshal([]byte(tokensJson), &tokens)
	if err != nil {
		return "", fmt.Errorf("failed to parse service account tokens from CSI volume context: %w",
			err)
	}

	apiToken, ok := tokens[""]
	if !ok || len(apiToken.Token) == 0 {
		return "", errors.New("empty audience service account token doesn't exist in CSI volume context, driver likely doesn't have an empty audience token request configured")
	}

	return apiToken.Token, nil
}
