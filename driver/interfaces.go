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

package driver

import (
	"crypto"
	"crypto/x509"

	"github.com/cert-manager/csi-lib/metadata"
)

// GeneratePrivateKeyFunc returns a private key to be used for issuance of the
// given request.
// Depending on the implementation, this may be a newly generated private key,
// one that has been read from disk, or even simply a pointer to an external
// signing device such as a HSM.
type GeneratePrivateKeyFunc func(meta metadata.Metadata) (crypto.PrivateKey, error)

// GenerateRequestFunc generates a new x509.CertificateRequest for the given
// metadata.
type GenerateRequestFunc func(meta metadata.Metadata) (*x509.CertificateRequest, error)

// SignRequestFunc returns the signed CSR bytes (in DER format) for the given
// x509.CertificateRequest.
type SignRequestFunc func(meta metadata.Metadata, request *x509.CertificateRequest) (csr []byte, err error)
