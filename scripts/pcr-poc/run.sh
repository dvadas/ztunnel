#!/usr/bin/env bash
# Orchestrates the ztunnel PCR PoC end-to-end on a local kind cluster.
#
# Steps:
#   1. (re-)create a kind cluster with PodCertificateRequest +
#      ConstrainedImpersonation feature gates enabled.
#   2. Cross-build linux-amd64 binaries for the signer and test client.
#   3. Build minimal docker images for both, load them into kind.
#   4. Apply the signer + RBAC manifests.
#   5. Wait for the test client pod to terminate, then dump its logs.
#
# Environment overrides:
#   KIND_NAME   default: ztunnel-pcr
#   ARCH        default: detected from `uname -m`. Must match kind node arch.
#   SKIP_KIND   if set, do not (re)create the kind cluster.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
KIND_NAME="${KIND_NAME:-ztunnel-pcr}"
KIND_CFG="${ROOT}/scripts/pcr-poc/kind-cluster.yaml"
MANIFESTS_DIR="${ROOT}/scripts/pcr-poc/manifests"
DOCKERFILE="${ROOT}/scripts/pcr-poc/Dockerfile"
BUILD_DIR="${ROOT}/out/pcr-poc"

case "$(uname -m)" in
  arm64|aarch64) ARCH="${ARCH:-arm64}" ;;
  x86_64|amd64)  ARCH="${ARCH:-amd64}" ;;
  *) echo "unsupported arch: $(uname -m)"; exit 1 ;;
esac

if [[ -z "${SKIP_KIND:-}" ]]; then
  echo "==> (re)creating kind cluster ${KIND_NAME}"
  kind delete cluster --name "${KIND_NAME}" 2>/dev/null || true
  kind create cluster --name "${KIND_NAME}" --config "${KIND_CFG}" --wait 120s
fi

KCTX="kind-${KIND_NAME}"
kubectl --context "${KCTX}" cluster-info > /dev/null

echo "==> verifying feature gates are active"
if ! kubectl --context "${KCTX}" api-resources --api-group=certificates.k8s.io 2>/dev/null \
        | grep -q '^podcertificaterequests'; then
  echo "ERROR: podcertificaterequests resource not present; check that"
  echo "       PodCertificateRequest feature gate + certificates.k8s.io/v1beta1"
  echo "       runtime config are enabled on this kind node image."
  exit 1
fi

echo "==> cross-building linux/${ARCH} binaries"
mkdir -p "${BUILD_DIR}/signer" "${BUILD_DIR}/client"
( cd "${ROOT}/tools/pcr-signer" && \
  CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" \
  go build -trimpath -ldflags='-s -w' -o "${BUILD_DIR}/signer/pcr-signer" . )
( cd "${ROOT}/tools/pcr-test-client" && \
  CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" \
  go build -trimpath -ldflags='-s -w' -o "${BUILD_DIR}/client/pcr-test-client" . )

build_image() {
  local name="$1" bin="$2" dir="$3"
  cat > "${dir}/Dockerfile" <<EOF
FROM gcr.io/distroless/static:nonroot
COPY ${bin} /app
USER 65532:65532
ENTRYPOINT ["/app"]
EOF
  docker build -t "${name}:dev" "${dir}" >/dev/null
}

echo "==> building docker images"
build_image ztunnel-pcr-signer pcr-signer "${BUILD_DIR}/signer"
build_image ztunnel-pcr-test-client pcr-test-client "${BUILD_DIR}/client"

echo "==> loading images into kind"
kind load docker-image --name "${KIND_NAME}" \
  ztunnel-pcr-signer:dev ztunnel-pcr-test-client:dev

echo "==> applying signer manifests"
kubectl --context "${KCTX}" apply -f "${MANIFESTS_DIR}/signer.yaml"
kubectl --context "${KCTX}" -n pcr-signer rollout status deploy/pcr-signer --timeout=120s

echo "==> applying e2e RBAC + test pods"
kubectl --context "${KCTX}" apply -f "${MANIFESTS_DIR}/e2e-rbac.yaml"

echo "==> waiting for app-target pod to be Running"
kubectl --context "${KCTX}" -n pcr-test wait --for=condition=Ready pod/app-target --timeout=120s

echo "==> waiting for test client to terminate"
for _ in $(seq 1 60); do
  phase=$(kubectl --context "${KCTX}" -n pcr-test get pod pcr-test-client \
           -o jsonpath='{.status.phase}' 2>/dev/null || true)
  if [[ "${phase}" == "Succeeded" || "${phase}" == "Failed" ]]; then
    break
  fi
  sleep 2
done

echo "==> client logs:"
kubectl --context "${KCTX}" -n pcr-test logs pcr-test-client | sed 's/^/  /'

echo "==> signer logs (last 20 lines):"
kubectl --context "${KCTX}" -n pcr-signer logs deploy/pcr-signer --tail=20 | sed 's/^/  /'

echo "==> issued PCRs:"
kubectl --context "${KCTX}" -n pcr-test get podcertificaterequests -o wide || true

phase=$(kubectl --context "${KCTX}" -n pcr-test get pod pcr-test-client \
          -o jsonpath='{.status.phase}' 2>/dev/null || true)
if [[ "${phase}" != "Succeeded" ]]; then
  echo "FAIL: test client phase=${phase}"
  exit 1
fi
echo "OK: PoC end-to-end test passed"
