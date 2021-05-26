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
