package manager

import (
	"crypto"
	"crypto/x509"
	"k8s.io/utils/clock"
	"math"
	"testing"
	"time"

	cmfake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	"github.com/go-logr/logr/testr"
	"k8s.io/apimachinery/pkg/util/wait"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
)

// Default namespace name used when constructing test fixtures.
var defaultTestNamespace = "default-testns-name"

// Self signed certificate valid for 'example.com' (and probably expired by the time this is read).
// This is used during test fixtures as the test driver attempts to parse the PEM certificate data,
// so we can't just use any random bytes.
var selfSignedExampleCertificate = []byte(`-----BEGIN CERTIFICATE-----
MIICxjCCAa6gAwIBAgIRAI0W8ofWt2fD+J7Cha10KwwwDQYJKoZIhvcNAQELBQAw
ADAeFw0yMjA5MTMwODI0MDBaFw0yMjEyMTIwODI0MDBaMAAwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDR2ktXXbuJPZhudwfbwiYuKjb7BfehfuRZtme4
HNvIhf0ABavuK4uRlKAKXRt1SZWMzm6P7NpTSOHjlxoBluZKFsgQbtNYYC8cBOMr
1TuU9UwAD6U4Lw+obWQppwaEYIifdSVWUqphRT2I6EJONEB9ZUr0gHMKJ2sjl163
WseSDyjPHkEM3wmpHpdDfYjNQRZ9sKB4J4/R8maW1IPpzltbryNQMfVJCYA7SjvJ
KZK5cyhabqNVeBhjBSp+UczQVrJ4ruam3i4LFUbu7DVJ/60C8knhFxGJZ5uaPbOd
eStraFOp50S3JbSpymq2m8c02ZsunUYiWCXGoh/UqrfYViVVAgMBAAGjOzA5MA4G
A1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMBkGA1UdEQEB/wQPMA2CC2V4YW1w
bGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQCkAvvWIUgdpuukL8nqX3850FtHl8r9
I9oCra4Tv7fxsggFMhIbrVUjzE0NCB/kTjr5j/KFid9TFtbBo7bvYRKI1Qx12y28
CTvY1y5BqFN/lT917B+8lrWyvxsbtQ0Xhvj9JgbLhGQutR4J+ee1sKZTPqP/sSGl
PfY1JD5zWYWXWweLAR9hTp62SL6KVfsTT77jw0foehEKxfJbZY2wkdUS5GFMB8/a
KQ+2l7/qPU8XL8whXEsifoJJ+U66v3cfsH0PIhTV2JKhagljdTVf333JBD/z49qv
vnEIALrtIClFU6D/mTU5wyHhN29llwfjUgJrmYWqoWTZSiwGS6YmZpry
-----END CERTIFICATE-----`)

func newDefaultTestOptions(t *testing.T) Options {
	return defaultTestOptions(t, Options{})
}

func defaultTestOptions(t *testing.T, opts Options) Options {
	var store storage.Interface
	if opts.MetadataReader == nil {
		store = storage.NewMemoryFS()
		opts.MetadataReader = store
	} else {
		store = opts.MetadataReader.(storage.Interface)
	}
	if opts.Clock == nil {
		opts.Clock = fakeclock.NewFakeClock(time.Now())
	}
	if opts.Log == nil {
		log := testr.New(t)
		opts.Log = &log
	}
	if opts.Client == nil {
		opts.Client = cmfake.NewSimpleClientset()
	}
	if opts.NodeID == "" {
		opts.NodeID = "test-node-id"
	}
	if opts.GeneratePrivateKey == nil {
		opts.GeneratePrivateKey = nothingGeneratePrivateKey
	}
	if opts.GenerateRequest == nil {
		opts.GenerateRequest = generateRequestInNamespace(defaultTestNamespace)
	}
	if opts.SignRequest == nil {
		opts.SignRequest = nothingSignRequest
	}
	if opts.WriteKeypair == nil {
		opts.WriteKeypair = persistingWriteKeypair(store, opts.Clock)
	}
	if opts.RenewalBackoffConfig == nil {
		opts.RenewalBackoffConfig = &wait.Backoff{Steps: math.MaxInt32} // backoff is always 0s for speedy tests
	}
	return opts
}

func nothingGeneratePrivateKey(meta metadata.Metadata) (crypto.PrivateKey, error) {
	return nil, nil
}

func generateRequestInNamespace(ns string) GenerateRequestFunc {
	return func(meta metadata.Metadata) (*CertificateRequestBundle, error) {
		return &CertificateRequestBundle{
			Namespace: ns,
		}, nil
	}
}

func nothingSignRequest(meta metadata.Metadata, key crypto.PrivateKey, request *x509.CertificateRequest) (csr []byte, err error) {
	return []byte{}, nil
}

func persistingWriteKeypair(store storage.Interface, clock clock.Clock) WriteKeypairFunc {
	return func(meta metadata.Metadata, key crypto.PrivateKey, chain []byte, ca []byte) error {
		store.WriteFiles(meta, map[string][]byte{
			"ca":   ca,
			"cert": chain,
		})
		nextIssuanceTime := clock.Now().Add(time.Hour)
		meta.NextIssuanceTime = &nextIssuanceTime
		return store.WriteMetadata(meta.VolumeID, meta)
	}
}
