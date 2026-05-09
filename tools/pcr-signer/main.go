// Standalone PodCertificateRequest signer for the ztunnel PCR PoC.
//
// Watches PCRs whose `spec.signerName` matches --signer-name, builds a
// SPIFFE leaf certificate addressed to
// `spiffe://<trust-domain>/ns/<namespace>/sa/<serviceAccountName>`
// using the public key from the supplied stub PKCS#10 CSR, signs it
// with a self-generated ECDSA root CA, and patches the PCR's status
// subresource with the issued chain.
//
// This is a single-binary PoC and is intentionally simple:
//   - generates its own ECDSA P-256 root CA on first start, persists it
//     to --ca-dir if writable so restarts keep the same root, and
//     otherwise keeps it in memory.
//   - exposes the root via /ca.crt for bootstrap scripts.
//   - does not retry signing failures beyond the informer's natural
//     re-list behaviour.
//
// In a real istiod-side implementation this would live next to the
// existing CA code in security/pkg/server/ca and reuse the cluster's
// configured root.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	certv1beta1 "k8s.io/api/certificates/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	conditionDenied = "Denied"
	conditionFailed = "Failed"
	conditionIssued = "Issued"
)

func main() {
	var (
		signerName  = flag.String("signer-name", "spiffe.istio.io/cluster.local", "Signer name we sign for.")
		trustDomain = flag.String("trust-domain", "cluster.local", "SPIFFE trust domain to embed in issued certs.")
		caDir       = flag.String("ca-dir", "/var/lib/pcr-signer", "Directory to persist the generated CA.")
		certTTL     = flag.Duration("cert-ttl", 24*time.Hour, "Lifetime of issued leaf certificates.")
		refreshFrac = flag.Float64("refresh-frac", 0.5, "Fraction of cert TTL after which kubelet should begin refreshing.")
		listenAddr  = flag.String("listen", ":8080", "Address for the /healthz and /ca.crt HTTP endpoints.")
		kubeconfig  = flag.String("kubeconfig", "", "Path to a kubeconfig (for out-of-cluster runs).")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg, err := buildRestConfig(*kubeconfig)
	if err != nil {
		log.Fatalf("kube config: %v", err)
	}
	cli, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("kube client: %v", err)
	}

	ca, err := loadOrGenerateCA(*caDir)
	if err != nil {
		log.Fatalf("ca: %v", err)
	}
	log.Printf("loaded CA: subject=%q notAfter=%s", ca.cert.Subject.CommonName, ca.cert.NotAfter.Format(time.RFC3339))

	ctx, cancel := signalContext()
	defer cancel()

	go serveCA(*listenAddr, ca)

	signer := &pcrSigner{
		client:      cli,
		signerName:  *signerName,
		trustDomain: *trustDomain,
		ca:          ca,
		ttl:         *certTTL,
		refreshFrac: *refreshFrac,
	}
	if err := signer.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("signer loop: %v", err)
	}
	log.Printf("shut down cleanly")
}

func buildRestConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

// ---- signer loop ---------------------------------------------------

type pcrSigner struct {
	client      kubernetes.Interface
	signerName  string
	trustDomain string
	ca          *caBundle
	ttl         time.Duration
	refreshFrac float64
}

func (s *pcrSigner) run(ctx context.Context) error {
	tweak := func(opts *metav1.ListOptions) {
		opts.FieldSelector = fields.OneTermEqualSelector("spec.signerName", s.signerName).String()
	}
	factory := informers.NewSharedInformerFactoryWithOptions(s.client, 10*time.Minute,
		informers.WithTweakListOptions(tweak))
	inf := factory.Certificates().V1beta1().PodCertificateRequests().Informer()

	enqueue := func(obj any) {
		pcr, ok := obj.(*certv1beta1.PodCertificateRequest)
		if !ok {
			tomb, isTomb := obj.(cache.DeletedFinalStateUnknown)
			if !isTomb {
				return
			}
			pcr, ok = tomb.Obj.(*certv1beta1.PodCertificateRequest)
			if !ok {
				return
			}
		}
		if err := s.handle(ctx, pcr); err != nil {
			log.Printf("handle %s/%s: %v", pcr.Namespace, pcr.Name, err)
		}
	}
	if _, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    enqueue,
		UpdateFunc: func(_, n any) { enqueue(n) },
	}); err != nil {
		return fmt.Errorf("add event handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		return errors.New("informer did not sync")
	}
	log.Printf("informer synced; watching PCRs for signer %q", s.signerName)

	<-ctx.Done()
	return ctx.Err()
}

func (s *pcrSigner) handle(ctx context.Context, in *certv1beta1.PodCertificateRequest) error {
	if in.Spec.SignerName != s.signerName {
		return nil
	}
	if in.Status.CertificateChain != "" {
		return nil
	}
	for _, c := range in.Status.Conditions {
		if c.Type == conditionDenied || c.Type == conditionFailed {
			return nil
		}
	}

	chain, beginRefreshAt, notBefore, notAfter, err := s.sign(in)
	if err != nil {
		return s.markCondition(ctx, in, conditionFailed, err.Error())
	}

	pcr, err := s.client.CertificatesV1beta1().PodCertificateRequests(in.Namespace).
		Get(ctx, in.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("re-get PCR: %w", err)
	}
	pcr.Status.CertificateChain = chain
	nb := metav1.NewTime(notBefore)
	br := metav1.NewTime(beginRefreshAt)
	na := metav1.NewTime(notAfter)
	pcr.Status.NotBefore = &nb
	pcr.Status.BeginRefreshAt = &br
	pcr.Status.NotAfter = &na
	pcr.Status.Conditions = upsertCondition(pcr.Status.Conditions, metav1.Condition{
		Type:               conditionIssued,
		Status:             metav1.ConditionTrue,
		Reason:             "Signed",
		Message:            "certificate issued by ztunnel-pcr-poc signer",
		LastTransitionTime: metav1.NewTime(time.Now()),
	})

	if _, err := s.client.CertificatesV1beta1().PodCertificateRequests(pcr.Namespace).
		UpdateStatus(ctx, pcr, metav1.UpdateOptions{}); err != nil {
		if apierrors.IsConflict(err) {
			log.Printf("conflict updating %s/%s status; informer will retry", pcr.Namespace, pcr.Name)
			return nil
		}
		return fmt.Errorf("update status: %w", err)
	}
	log.Printf("issued cert for %s/%s sa=%s pod=%s notAfter=%s",
		pcr.Namespace, pcr.Name, pcr.Spec.ServiceAccountName, pcr.Spec.PodName, notAfter.Format(time.RFC3339))
	return nil
}

func (s *pcrSigner) markCondition(ctx context.Context, in *certv1beta1.PodCertificateRequest, ctype, msg string) error {
	pcr, err := s.client.CertificatesV1beta1().PodCertificateRequests(in.Namespace).
		Get(ctx, in.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("re-get PCR: %w", err)
	}
	for _, c := range pcr.Status.Conditions {
		if c.Type == ctype {
			return nil
		}
	}
	pcr.Status.Conditions = append(pcr.Status.Conditions, metav1.Condition{
		Type:               ctype,
		Status:             metav1.ConditionTrue,
		Reason:             "SignerError",
		Message:            msg,
		LastTransitionTime: metav1.NewTime(time.Now()),
	})
	_, err = s.client.CertificatesV1beta1().PodCertificateRequests(pcr.Namespace).
		UpdateStatus(ctx, pcr, metav1.UpdateOptions{})
	if err != nil && !apierrors.IsConflict(err) {
		return fmt.Errorf("write %s condition: %w", ctype, err)
	}
	log.Printf("marked %s/%s as %s: %s", pcr.Namespace, pcr.Name, ctype, msg)
	return nil
}

func (s *pcrSigner) sign(in *certv1beta1.PodCertificateRequest) (chain string, beginRefreshAt, notBefore, notAfter time.Time, err error) {
	pubKey, err := extractPublicKey(in)
	if err != nil {
		return "", time.Time{}, time.Time{}, time.Time{}, err
	}

	spiffeURI := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s",
		s.trustDomain, in.Namespace, in.Spec.ServiceAccountName)
	uri, err := url.Parse(spiffeURI)
	if err != nil {
		return "", time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("build SPIFFE URI: %w", err)
	}

	ttl := s.ttl
	if in.Spec.MaxExpirationSeconds != nil {
		requested := time.Duration(*in.Spec.MaxExpirationSeconds) * time.Second
		if requested > 0 && requested < ttl {
			ttl = requested
		}
	}

	notBefore = time.Now().Add(-1 * time.Minute) // small clock-skew tolerance
	notAfter = notBefore.Add(ttl)
	beginRefreshAt = notBefore.Add(time.Duration(float64(ttl) * s.refreshFrac))

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"ztunnel-pcr-poc"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca.cert, pubKey, s.ca.key)
	if err != nil {
		return "", time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("sign cert: %w", err)
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.ca.cert.Raw})
	chain = string(leafPEM) + string(rootPEM)
	return chain, beginRefreshAt, notBefore, notAfter, nil
}

// ---- CA ------------------------------------------------------------

type caBundle struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func (b *caBundle) certPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.cert.Raw})
}

func loadOrGenerateCA(dir string) (*caBundle, error) {
	keyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "ca.crt")

	if dir != "" {
		if k, c, err := readCA(keyPath, certPath); err == nil {
			return &caBundle{key: k, cert: c}, nil
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ztunnel-pcr-poc-root",
			Organization: []string{"ztunnel-pcr-poc"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create ca cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}

	if dir != "" {
		_ = os.MkdirAll(dir, 0o700)
		if err := writeCA(keyPath, certPath, key, der); err != nil {
			log.Printf("warning: persisting CA failed (%v); continuing in memory", err)
		}
	}
	return &caBundle{key: key, cert: cert}, nil
}

func readCA(keyPath, certPath string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	cb, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(kb)
	if keyBlock == nil {
		return nil, nil, errors.New("no PEM block in ca.key")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca key: %w", err)
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected ca key type %T", keyAny)
	}
	certBlock, _ := pem.Decode(cb)
	if certBlock == nil {
		return nil, nil, errors.New("no PEM block in ca.crt")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca cert: %w", err)
	}
	return key, cert, nil
}

func writeCA(keyPath, certPath string, key *ecdsa.PrivateKey, certDER []byte) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
		return err
	}
	return nil
}

// serveCA exposes the CA root cert so the e2e test can fetch it without
// needing the Kube client.
func serveCA(addr string, ca *caBundle) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/ca.crt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(ca.certPEM())
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("HTTP serving on %s (/healthz, /ca.crt)", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("http server: %v", err)
	}
}

// ---- helpers -------------------------------------------------------

// extractPublicKey returns the requesting workload's public key. It
// prefers StubPKCS10Request (the 1.36+ canonical input) and falls back
// to the legacy PKIXPublicKey field which is still the primary input on
// 1.35.
func extractPublicKey(in *certv1beta1.PodCertificateRequest) (any, error) {
	if len(in.Spec.StubPKCS10Request) > 0 {
		csr, err := decodeStubCSR(in.Spec.StubPKCS10Request)
		if err != nil {
			return nil, fmt.Errorf("decode CSR: %w", err)
		}
		if err := csr.CheckSignature(); err != nil {
			return nil, fmt.Errorf("CSR signature invalid: %w", err)
		}
		return csr.PublicKey, nil
	}
	if len(in.Spec.PKIXPublicKey) == 0 {
		return nil, errors.New("PCR has neither StubPKCS10Request nor PKIXPublicKey set")
	}
	pub, err := x509.ParsePKIXPublicKey(in.Spec.PKIXPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse PKIXPublicKey: %w", err)
	}
	return pub, nil
}

// decodeStubCSR accepts the raw DER-or-PEM bytes from
// `spec.stubPKCS10Request`. The kube apiserver auto-base64-decodes the
// JSON value into the []byte field, so we get binary here.
func decodeStubCSR(raw []byte) (*x509.CertificateRequest, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty stubPKCS10Request")
	}
	if blk, _ := pem.Decode(raw); blk != nil {
		return x509.ParseCertificateRequest(blk.Bytes)
	}
	return x509.ParseCertificateRequest(raw)
}

// upsertCondition replaces a Condition of the same type, or appends it.
func upsertCondition(conds []metav1.Condition, c metav1.Condition) []metav1.Condition {
	for i := range conds {
		if conds[i].Type == c.Type {
			conds[i] = c
			return conds
		}
	}
	return append(conds, c)
}
