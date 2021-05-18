package manager

import (
	"crypto"
	"crypto/x509"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"

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
type GenerateRequestFunc func(meta metadata.Metadata) (*CertificateRequestBundle, error)

// A CertificateRequestBundle contains information to be persisted onto the
// CertificateRequest resource created for a given CSR.
// This includes the CSR itself, as well as the requested `usages`, `isCA` bit,
// `issuerRef` and any additional annotations.
type CertificateRequestBundle struct {
	// The x509 certificate request.
	// This is expected to be unsigned, as the SignRequestFunc will sign it
	// at a later stage.
	Request *x509.CertificateRequest

	// List of certificate usages to be added to the request.
	Usages []cmapi.KeyUsage

	// Whether the requested certificate should have the `isCA` bit set.
	IsCA bool

	// Namespace that the CertificateRequest should be created in.
	Namespace string

	// The IssuerRef to be added to the CertificateRequest.
	IssuerRef cmmeta.ObjectReference

	// Request duration/validity period of the certificate
	Duration time.Duration

	// Additional annotations to add to the CertificateRequest object when
	// created.
	Annotations map[string]string
}

// SignRequestFunc returns the signed CSR bytes (in PEM format) for the given
// x509.CertificateRequest.
// The private key passed to this function is one that is returned by the
// GeneratePrivateKeyFunc and should be treated as implementation specific.
// For example, it may be a reference to a location where a private key is
// stored rather than containing actual private key data.
type SignRequestFunc func(meta metadata.Metadata, key crypto.PrivateKey, request *x509.CertificateRequest) (pem []byte, err error)

// WriteKeypairFunc encodes & persists the output from a completed CertificateRequest
// into whatever storage backend is provided.
// The 'key' argument is as returned by the GeneratePrivateKeyFunc.
// The 'chain' and 'ca' arguments are PEM encoded and sourced directly from the
// CertificateRequest, without any attempt to parse or decode the bytes.
type WriteKeypairFunc func(meta metadata.Metadata, key crypto.PrivateKey, chain []byte, ca []byte) error
