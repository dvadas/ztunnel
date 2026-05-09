// e2e test client for the ztunnel PCR PoC.
//
// Mirrors what `src/identity/pcr_client.rs` does, but in Go so it can
// run inside the kind cluster without depending on the ztunnel binary.
//
// Behaviour:
//  1. Reads its own node name (downward API), namespace, and target
//     ServiceAccount name from env.
//  2. Loads the node-bound SA token (KEP-4193) from the projected
//     volume mount.
//  3. Looks up the target Pod (must be on this node), Pod UID, target
//     SA UID, and Node UID via the kube API using its own SA token.
//  4. Generates an in-memory ECDSA P-256 key + PKCS#10 CSR with the
//     SPIFFE URI it expects to receive.
//  5. POSTs a PodCertificateRequest with header
//     `Impersonate-User: system:node:<NODE_NAME>` (constrained
//     impersonation, KEP-5284). The kube-apiserver verifies that
//     the impersonated node matches the bound token's node-name extra,
//     and that the spec's pod/SA/node UIDs are consistent with a real
//     pod via the noderestriction admission plugin.
//  6. Polls until the PCR's status is populated, then validates the
//     issued chain against the signer's CA and prints success.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	certv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	var (
		signerName  = envOr("SIGNER_NAME", "spiffe.istio.io/cluster.local")
		trustDomain = envOr("TRUST_DOMAIN", "cluster.local")
		nodeName    = mustEnv("NODE_NAME")
		ns          = mustEnv("POD_NAMESPACE")
		targetSA    = envOr("TARGET_SA", "app")
		caURL       = envOr("PCR_SIGNER_CA_URL", "http://pcr-signer.pcr-signer.svc/ca.crt")
		kubeconfig  = flag.String("kubeconfig", "", "Path to a kubeconfig (out-of-cluster).")
		timeoutFlag = flag.Duration("timeout", 90*time.Second, "Overall test timeout.")
	)
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	cfg, err := buildRestConfig(*kubeconfig)
	if err != nil {
		log.Fatalf("kube config: %v", err)
	}
	cli, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("kube client: %v", err)
	}

	pod, err := findTargetPod(ctx, cli, ns, targetSA, nodeName)
	if err != nil {
		log.Fatalf("find target pod: %v", err)
	}
	saUID, err := getSAUID(ctx, cli, ns, targetSA)
	if err != nil {
		log.Fatalf("get SA uid: %v", err)
	}
	nodeUID, err := getNodeUID(ctx, cli, nodeName)
	if err != nil {
		log.Fatalf("get node uid: %v", err)
	}
	log.Printf("target pod=%s/%s uid=%s saUID=%s nodeUID=%s", pod.Namespace, pod.Name, pod.UID, saUID, nodeUID)

	wantSPIFFE := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, ns, targetSA)
	key, csrDER, err := generateKeyAndCSR(wantSPIFFE)
	if err != nil {
		log.Fatalf("csr: %v", err)
	}

	// The v1beta1 PCR API still requires the (deprecated) PKIXPublicKey
	// + ProofOfPossession fields in 1.35; the StubPKCS10Request field
	// becomes the sole input in 1.36. We populate all three so the same
	// PoC works on both.
	pkixPub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatalf("marshal PKIX pubkey: %v", err)
	}
	pop, err := ecdsa.SignASN1(rand.Reader, key, sha256Sum([]byte(pod.UID)))
	if err != nil {
		log.Fatalf("proof of possession: %v", err)
	}

	// Build the impersonating client.
	impersonatingCfg, err := nodeImpersonatingConfig(cfg, nodeName)
	if err != nil {
		log.Fatalf("impersonating config: %v", err)
	}
	impCli, err := kubernetes.NewForConfig(impersonatingCfg)
	if err != nil {
		log.Fatalf("impersonating kube client: %v", err)
	}

	maxExp := int32(3600)
	pcr := &certv1beta1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "ztunnel-poc-",
			Namespace:    ns,
		},
		Spec: certv1beta1.PodCertificateRequestSpec{
			SignerName:           signerName,
			PodName:              pod.Name,
			PodUID:               pod.UID,
			ServiceAccountName:   targetSA,
			ServiceAccountUID:    types.UID(saUID),
			NodeName:             types.NodeName(nodeName),
			NodeUID:              types.UID(nodeUID),
			MaxExpirationSeconds: &maxExp,
			PKIXPublicKey:        pkixPub,
			ProofOfPossession:    pop,
			StubPKCS10Request:    csrDER,
		},
	}
	created, err := impCli.CertificatesV1beta1().PodCertificateRequests(ns).
		Create(ctx, pcr, metav1.CreateOptions{})
	if err != nil {
		log.Fatalf("create PCR: %v", err)
	}
	log.Printf("created PCR %s/%s", created.Namespace, created.Name)

	chainPEM, err := waitForCert(ctx, impCli, created.Namespace, created.Name)
	if err != nil {
		log.Fatalf("wait for cert: %v", err)
	}
	log.Printf("got chain (%d bytes)", len(chainPEM))

	caPEM, err := fetchCA(ctx, caURL)
	if err != nil {
		log.Fatalf("fetch CA: %v", err)
	}
	if err := verifyChain(chainPEM, caPEM, key, wantSPIFFE); err != nil {
		log.Fatalf("verify chain: %v", err)
	}
	fmt.Println("PASS: PodCertificateRequest issued and verified")
	fmt.Printf("  spiffe: %s\n", wantSPIFFE)
	fmt.Printf("  pcr:    %s/%s\n", created.Namespace, created.Name)
}

// ---- discovery helpers ---------------------------------------------

func findTargetPod(ctx context.Context, cli kubernetes.Interface, ns, sa, node string) (*corev1.Pod, error) {
	list, err := cli.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", node).String(),
	})
	if err != nil {
		return nil, err
	}
	for i := range list.Items {
		p := &list.Items[i]
		if p.Spec.ServiceAccountName != sa {
			continue
		}
		switch p.Status.Phase {
		case corev1.PodPending, corev1.PodRunning:
			return p, nil
		}
	}
	return nil, fmt.Errorf("no Pending/Running pod with SA %q on node %q in namespace %q", sa, node, ns)
}

func getSAUID(ctx context.Context, cli kubernetes.Interface, ns, name string) (string, error) {
	sa, err := cli.CoreV1().ServiceAccounts(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return string(sa.UID), nil
}

func getNodeUID(ctx context.Context, cli kubernetes.Interface, name string) (string, error) {
	n, err := cli.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return string(n.UID), nil
}

// ---- key + CSR -----------------------------------------------------

func generateKeyAndCSR(spiffeURI string) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	uri, err := url.Parse(spiffeURI)
	if err != nil {
		return nil, nil, fmt.Errorf("parse SPIFFE URI: %w", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{Organization: []string{"ztunnel-pcr-poc"}},
		URIs:    []*url.URL{uri},
	}
	// Per the v1beta1 PCR spec, StubPKCS10Request must be DER-encoded.
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create csr: %w", err)
	}
	return key, der, nil
}

// ---- impersonating client ------------------------------------------

// nodeImpersonatingConfig clones the in-cluster rest.Config and adds an
// `Impersonate-User: system:node:<nodeName>` header to every request.
// The base SA token (mounted via the standard projected volume) carries
// the `authentication.kubernetes.io/node-name` extra (KEP-4193) which
// the apiserver uses to authorise `impersonate:associated-node`.
func nodeImpersonatingConfig(base *rest.Config, nodeName string) (*rest.Config, error) {
	out := rest.CopyConfig(base)
	out.Impersonate = rest.ImpersonationConfig{
		UserName: "system:node:" + nodeName,
	}
	return out, nil
}

// ---- wait for issuance ---------------------------------------------

func waitForCert(ctx context.Context, cli kubernetes.Interface, ns, name string) (string, error) {
	deadline, hasDeadline := ctx.Deadline()
	for {
		pcr, err := cli.CertificatesV1beta1().PodCertificateRequests(ns).
			Get(ctx, name, metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return "", err
		}
		if pcr != nil {
			for _, c := range pcr.Status.Conditions {
				if c.Type == "Denied" {
					return "", fmt.Errorf("PCR denied: %s", c.Message)
				}
				if c.Type == "Failed" {
					return "", fmt.Errorf("PCR failed: %s", c.Message)
				}
			}
			if pcr.Status.CertificateChain != "" {
				return pcr.Status.CertificateChain, nil
			}
		}
		if hasDeadline && time.Now().After(deadline) {
			return "", errors.New("timed out waiting for PCR status")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// ---- verification --------------------------------------------------

func verifyChain(chainPEM, rootPEM string, key *ecdsa.PrivateKey, wantSPIFFE string) error {
	leaf, intermediates, err := splitChain(chainPEM)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(rootPEM)) {
		return errors.New("could not parse signer CA PEM")
	}
	intPool := x509.NewCertPool()
	for _, c := range intermediates {
		intPool.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("verify chain: %w", err)
	}
	leafKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("unexpected leaf public key type %T", leaf.PublicKey)
	}
	if leafKey.X.Cmp(key.PublicKey.X) != 0 || leafKey.Y.Cmp(key.PublicKey.Y) != 0 {
		return errors.New("leaf public key does not match the key we generated")
	}
	found := false
	for _, u := range leaf.URIs {
		if u.String() == wantSPIFFE {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("leaf SAN does not contain expected SPIFFE URI %s; got %v", wantSPIFFE, leaf.URIs)
	}
	return nil
}

func splitChain(chainPEM string) (*x509.Certificate, []*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(chainPEM)
	for {
		blk, next := pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parse cert: %w", err)
			}
			certs = append(certs, c)
		}
		rest = next
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("chain contained no CERTIFICATE blocks")
	}
	if len(certs) == 1 {
		return certs[0], nil, nil
	}
	return certs[0], certs[1:], nil
}

// ---- misc ----------------------------------------------------------

func fetchCA(ctx context.Context, urlStr string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("fetch CA %s: status %s", urlStr, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	return string(b), err
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

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("env %s must be set", k)
	}
	return v
}

func sha256Sum(in []byte) []byte {
	h := sha256.Sum256(in)
	return h[:]
}
