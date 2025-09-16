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

package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	"github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/csi-lib/driver"
	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/metrics"
	"github.com/cert-manager/csi-lib/storage"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2/klogr"
	"k8s.io/utils/clock"
)

const (
	IssuerNameKey  string = "csi.cert-manager.io/issuer-name"
	IssuerKindKey  string = "csi.cert-manager.io/issuer-kind"
	IssuerGroupKey string = "csi.cert-manager.io/issuer-group"

	CommonNameKey string = "csi.cert-manager.io/common-name"
	DNSNamesKey   string = "csi.cert-manager.io/dns-names"
	IPSANsKey     string = "csi.cert-manager.io/ip-sans"
	URISANsKey    string = "csi.cert-manager.io/uri-sans"
	DurationKey   string = "csi.cert-manager.io/duration"
	IsCAKey       string = "csi.cert-manager.io/is-ca"
	KeyUsagesKey  string = "csi.cert-manager.io/key-usages"

	CAFileKey   string = "csi.cert-manager.io/ca-file"
	CertFileKey string = "csi.cert-manager.io/certificate-file"
	KeyFileKey  string = "csi.cert-manager.io/privatekey-file"

	RenewBeforeKey  string = "csi.cert-manager.io/renew-before"
	ReusePrivateKey string = "csi.cert-manager.io/reuse-private-key"

	// fs-group is used to optionally set the GID ownership of the volume's
	// files. Useful when running containers with a specified user and group.
	FsGroupKey string = "csi.cert-manager.io/fs-group"
)

var (
	nodeID   = flag.String("node-id", "", "Name of the node the driver is running on")
	endpoint = flag.String("endpoint", "", "Path to the unix socket used to listen for gRPC requests")
	dataRoot = flag.String("data-root", "", "Path to the in-memory data directory used to store data")
)

func main() {
	flag.Parse()

	if *nodeID == "" {
		panic("-node-id must be set")
	}
	if *endpoint == "" {
		panic("-endpoint must be set")
	}
	if *dataRoot == "" {
		panic("-data-root must be set")
	}

	log := klogr.New()

	restConfig, err := rest.InClusterConfig()
	if err != nil {
		panic("cannot load in-cluster config")
	}

	store, err := storage.NewFilesystem(log, *dataRoot)
	if err != nil {
		panic("failed to setup filesystem: " + err.Error())
	}

	store.FSGroupVolumeAttributeKey = FsGroupKey

	cmClient := cmclient.NewForConfigOrDie(restConfig)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	metricsHandler, err := startMetricsServer(ctx, *nodeID, log, cmClient, store)
	if err != nil {
		panic("failed to setup metrics server: " + err.Error())
	}

	d, err := driver.New(ctx, *endpoint, log, driver.Options{
		DriverName:    "csi.cert-manager.io",
		DriverVersion: "v0.0.1",
		NodeID:        *nodeID,
		Store:         store,
		Manager: manager.NewManagerOrDie(manager.Options{
			Client:             cmClient,
			MetadataReader:     store,
			Clock:              clock.RealClock{},
			Log:                &log,
			NodeID:             *nodeID,
			GeneratePrivateKey: (&keygen{store: store}).generatePrivateKey,
			GenerateRequest:    generateRequest,
			SignRequest:        signRequest,
			WriteKeypair:       (&writer{store: store}).writeKeypair,
			Metrics:            metricsHandler,
		}),
	})
	if err != nil {
		panic("failed to setup driver: " + err.Error())
	}

	if err := d.Run(); err != nil {
		panic("failed running driver: " + err.Error())
	}
}

// keygen wraps the storage backend to allow for re-using private keys when
// re-issuing a certificate.
type keygen struct {
	store *storage.Filesystem
}

// generatePrivateKey generates a 2048-bit RSA private key
func (k *keygen) generatePrivateKey(meta metadata.Metadata) (crypto.PrivateKey, error) {
	// Currently no options are exposed for customising the kind of key generated
	genPrivateKey := func() (crypto.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }

	// By default, generate a new private key each time.
	if meta.VolumeContext[ReusePrivateKey] != "true" {
		return genPrivateKey()
	}

	bytes, err := k.store.ReadFile(meta.VolumeID, "tls.key")
	if errors.Is(err, storage.ErrNotFound) {
		// Generate a new key if one is not found on disk
		return genPrivateKey()
	}

	pk, err := pki.DecodePrivateKeyBytes(bytes)
	if err != nil {
		// Generate a new key if the existing one cannot be decoded
		return genPrivateKey()
	}

	return pk, nil
}

func generateRequest(meta metadata.Metadata) (*manager.CertificateRequestBundle, error) {
	namespace := meta.VolumeContext["csi.storage.k8s.io/pod.namespace"]

	uris, err := parseURIs(meta.VolumeContext[URISANsKey])
	if err != nil {
		return nil, fmt.Errorf("invalid URI provided in %q attribute: %w", URISANsKey, err)
	}

	ips := parseIPAddresses(meta.VolumeContext[IPSANsKey])

	dnsNames := strings.Split(meta.VolumeContext[DNSNamesKey], ",")
	commonName := meta.VolumeContext[CommonNameKey]

	duration := cmapi.DefaultCertificateDuration
	if durStr, ok := meta.VolumeContext[DurationKey]; ok {
		duration, err = time.ParseDuration(durStr)
		if err != nil {
			return nil, fmt.Errorf("invalid %q attribute: %w", DurationKey, err)
		}
	}

	isCA := false
	if isCAStr, ok := meta.VolumeContext[IsCAKey]; ok {
		switch strings.ToLower(isCAStr) {
		case "true":
			isCA = true
		case "false":
			isCA = false
		}
	}

	return &manager.CertificateRequestBundle{
		Request: &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: commonName,
			},
			DNSNames:    dnsNames,
			IPAddresses: ips,
			URIs:        uris,
		},
		IsCA:      isCA,
		Namespace: namespace,
		Duration:  duration,
		Usages:    keyUsagesFromAttributes(meta.VolumeContext[KeyUsagesKey]),
		IssuerRef: cmmeta.ObjectReference{
			Name:  meta.VolumeContext[IssuerNameKey],
			Kind:  meta.VolumeContext[IssuerKindKey],
			Group: meta.VolumeContext[IssuerGroupKey],
		},
		Annotations: nil,
	}, nil
}

func signRequest(_ metadata.Metadata, key crypto.PrivateKey, request *x509.CertificateRequest) ([]byte, error) {
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDer,
	}), nil
}

// writer wraps the storage backend to allow access for writing data
type writer struct {
	store storage.Interface
}

func (w *writer) writeKeypair(meta metadata.Metadata, key crypto.PrivateKey, chain []byte, ca []byte) error {
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey)),
		},
	)

	pkFile := "tls.key"
	if meta.VolumeContext[KeyFileKey] != "" {
		pkFile = meta.VolumeContext[KeyFileKey]
	}
	crtFile := "tls.crt"
	if meta.VolumeContext[CertFileKey] != "" {
		crtFile = meta.VolumeContext[CertFileKey]
	}
	caFile := "ca.crt"
	if meta.VolumeContext[CAFileKey] != "" {
		caFile = meta.VolumeContext[CAFileKey]
	}

	nextIssuanceTime, err := calculateNextIssuanceTime(meta, chain)
	if err != nil {
		return fmt.Errorf("calculating next issuance time: %w", err)
	}

	if err := w.store.WriteFiles(meta, map[string][]byte{
		pkFile:  keyPEM,
		crtFile: chain,
		caFile:  ca,
	}); err != nil {
		return fmt.Errorf("writing data: %w", err)
	}

	meta.NextIssuanceTime = &nextIssuanceTime
	if err := w.store.WriteMetadata(meta.VolumeID, meta); err != nil {
		return fmt.Errorf("writing metadata: %w", err)
	}

	return nil
}

func calculateNextIssuanceTime(meta metadata.Metadata, chain []byte) (time.Time, error) {
	block, _ := pem.Decode(chain)
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing issued certificate: %w", err)
	}

	actualDuration := crt.NotAfter.Sub(crt.NotBefore)
	// if not explicitly set, renew once a certificate is 2/3rds of the way through its lifetime
	renewBeforeNotAfter := actualDuration / 3
	if meta.VolumeContext[RenewBeforeKey] != "" {
		renewBeforeDuration, err := time.ParseDuration(meta.VolumeContext[RenewBeforeKey])
		if err != nil {
			return time.Time{}, fmt.Errorf("parsing requested renew-before duration: %w", err)
		}

		// If the requested renewBefore would cause the certificate to be immediately re-issued,
		// ignore the requested renew before and renew 2/3rds of the way through its lifetime.
		if crt.NotBefore.Add(renewBeforeDuration).Before(crt.NotAfter) {
			renewBeforeNotAfter = renewBeforeDuration
		}
	}

	return crt.NotAfter.Add(-renewBeforeNotAfter), nil
}

func parseIPAddresses(ips string) []net.IP {
	if len(ips) == 0 {
		return nil
	}

	ipsS := strings.Split(ips, ",")

	var ipAddresses []net.IP

	for _, ipName := range ipsS {
		ip := net.ParseIP(ipName)
		if ip != nil {
			ipAddresses = append(ipAddresses, ip)
		}
	}

	return ipAddresses
}

func parseURIs(uris string) ([]*url.URL, error) {
	if len(uris) == 0 {
		return nil, nil
	}

	urisS := strings.Split(uris, ",")

	var urisURL []*url.URL

	for _, uriS := range urisS {
		uri, err := url.Parse(uriS)
		if err != nil {
			return nil, err
		}

		urisURL = append(urisURL, uri)
	}

	return urisURL, nil
}

func keyUsagesFromAttributes(usagesCSV string) []cmapi.KeyUsage {
	if len(usagesCSV) == 0 {
		return nil
	}

	var keyUsages []cmapi.KeyUsage
	for usage := range strings.SplitSeq(usagesCSV, ",") {
		keyUsages = append(keyUsages, cmapi.KeyUsage(strings.TrimSpace(usage)))
	}

	return keyUsages
}

// startMetricsServer starts a server listening on port 6443, until the supplied context is cancelled,
// after which the server will gracefully shutdown (within 5 seconds).
func startMetricsServer(
	rootCtx context.Context,
	nodeId string,
	logger logr.Logger,
	cmClient *cmclient.Clientset,
	metadataReader storage.MetadataReader,
) (*metrics.Metrics, error) {
	g, ctx := errgroup.WithContext(rootCtx)
	defer func() {
		if err := g.Wait(); err != nil {
			logger.Error(err, "fail to stop metric server")
		}
	}()

	metricsHandler := metrics.New(&logger, prometheus.NewRegistry())

	certRequestInformerFactory := externalversions.NewSharedInformerFactory(cmClient, 5*time.Second)
	certRequestInformer := certRequestInformerFactory.Certmanager().V1().CertificateRequests()
	metricsHandler.SetupCertificateRequestCollector(nodeId, metadataReader, certRequestInformer.Lister())

	listenConfig := &net.ListenConfig{}
	metricsLn, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:6443")
	if err != nil {
		return nil, err
	}
	metricsServer := &http.Server{
		Addr:           metricsLn.Addr().String(),
		ReadTimeout:    8 * time.Second,
		WriteTimeout:   8 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MiB
		Handler:        metricsHandler.DefaultHandler(),
	}

	g.Go(func() error {
		certRequestInformerFactory.Start(ctx.Done())
		certRequestInformerFactory.WaitForCacheSync(ctx.Done())
		return nil
	})
	g.Go(func() error {
		<-rootCtx.Done()
		// allow a timeout for graceful shutdown
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// nolint: contextcheck
		return metricsServer.Shutdown(shutdownCtx)
	})
	g.Go(func() error {
		logger.Info("starting metrics server", "address", metricsLn.Addr())
		if err := metricsServer.Serve(metricsLn); err != http.ErrServerClosed {
			return err
		}
		return nil
	})
	return metricsHandler, nil
}
