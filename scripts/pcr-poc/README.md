# ztunnel PCR PoC

A self-contained end-to-end demonstration that ztunnel could mint
workload mTLS certificates via the upstream Kubernetes
`PodCertificateRequest` API (KEP-4317) using constrained impersonation
(KEP-5284), instead of the existing istiod gRPC `IstioCertificateService`
+ `ImpersonatedIdentity` path.

What this PoC contains:

| Component | Path | Role |
| --- | --- | --- |
| ztunnel `PcrCaClient` | [src/identity/pcr_client.rs](../../src/identity/pcr_client.rs) | Implements `CaClientTrait` against PCR. Selected when `CA_PROVIDER=PodCertificateRequest`. |
| Standalone signer | [tools/pcr-signer/](../../tools/pcr-signer/) | Watches PCRs, signs SPIFFE leaf certs with a self-generated ECDSA root. Stand-in for an istiod-side signer controller. |
| e2e test client | [tools/pcr-test-client/](../../tools/pcr-test-client/) | Acts like ztunnel: impersonates `system:node:<itsNode>`, creates a PCR for a target pod's SA, validates the issued chain. |
| kind config | [kind-cluster.yaml](kind-cluster.yaml) | Enables `PodCertificateRequest` and `ConstrainedImpersonation` feature gates + the `certificates.k8s.io/v1beta1` runtime API. |
| Manifests | [manifests/](manifests/) | RBAC for the signer and the test client. |
| Driver | [run.sh](run.sh) | Builds, loads, applies everything, then prints the result. |

## Requirements

- Docker
- `kind` (tested with v0.31)
- `kubectl` v1.35+
- Go 1.24+

## Run

```bash
./scripts/pcr-poc/run.sh
```

Expected last lines of output:

```
PASS: PodCertificateRequest issued and verified
  spiffe: spiffe://cluster.local/ns/pcr-test/sa/app
  pcr:    pcr-test/ztunnel-poc-XXXXX
OK: PoC end-to-end test passed
```

## What this proves

1. The kube apiserver accepts `PodCertificateRequest` objects created by
   a daemon authenticated as a non-node SA, **only** because the
   constrained-impersonation grants in [e2e-rbac.yaml](manifests/e2e-rbac.yaml)
   allow it to act as `system:node:<itsNode>`. Removing either the
   `impersonate:associated-node` ClusterRoleBinding or the
   `impersonate-on:associated-node:create` Role grant produces a 403.
2. The `noderestriction` admission plugin rejects PCRs that do not match
   a real pod with the correct SA on the impersonated node — the same
   security property istiod enforces today in
   `security/pkg/server/ca/node_auth.go`, but moved into upstream
   Kubernetes.
3. The signer never sees a bearer token from the requesting workload —
   it only authenticates to kube-apiserver via its own client cert.

## What this does not yet do

- No istiod-side integration. The signer is a separate pod.
- No ambient/HBONE traffic test — only the cert issuance path.
- No multi-node coverage of `noderestriction` rejection paths (planned
  as a follow-up: a negative test that creates a PCR for a pod on a
  different node should be 403'd by admission).
- ztunnel's `PcrCaClient` is built and unit-tested but not exercised in
  the kind cluster (would require packaging ztunnel into the cluster
  with a CNI). The Go test client mirrors its on-the-wire behaviour
  exactly so the PoC validates the same flow.
