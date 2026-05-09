// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! PodCertificateRequest CA client.
//!
//! Implements `CaClientTrait` against the Kubernetes
//! `certificates.k8s.io/v1beta1.PodCertificateRequest` API (KEP-4317).
//!
//! Uses constrained impersonation (KEP-5284) to act as
//! `system:node:<NODE_NAME>` when creating PCRs on behalf of pods running
//! on the local node. The Kubernetes `noderestriction` admission plugin
//! then enforces that the impersonated node matches the pod's
//! `spec.nodeName`, replacing Istio's custom `node_auth.go` check.
//!
//! The PCR is signed by a controller (in this PoC, a standalone Go
//! binary) that watches PCRs addressed to a particular signer name and
//! writes the issued chain to `status.certificateChain`. The signer
//! embeds the SPIFFE URI for the requesting pod's ServiceAccount in the
//! leaf certificate's Subject Alternative Names.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{debug, instrument, warn};

use crate::identity::Error;
use crate::identity::manager::Identity;
use crate::tls;
use crate::tls::crypto_provider;

const CONTENT_TYPE_JSON: &str = "application/json";
const PCR_API_PREFIX: &str = "/apis/certificates.k8s.io/v1beta1";
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const POLL_TIMEOUT: Duration = Duration::from_secs(60);

/// Configuration for [`PcrCaClient`].
#[derive(Clone, Debug)]
pub struct PcrConfig {
    /// Kubernetes API server base URL, e.g. `https://kubernetes.default.svc:443`.
    pub apiserver_url: String,
    /// Path to the kube apiserver CA bundle (PEM). Defaults to the
    /// in-cluster service account CA path.
    pub ca_bundle_path: PathBuf,
    /// Path to the ServiceAccount token. Re-read on every request to
    /// pick up rotated tokens.
    pub token_path: PathBuf,
    /// Local node name. Used both as the impersonated node identity
    /// and to filter pods to those scheduled on this node.
    pub node_name: String,
    /// Signer name addressed in created PodCertificateRequests, e.g.
    /// `spiffe.istio.io/cluster.local`.
    pub signer_name: String,
    /// Trust domain to embed in SPIFFE URIs (matches the signer's
    /// configured trust domain).
    pub trust_domain: String,
    /// Maximum certificate lifetime requested in the PCR. Both
    /// kube-apiserver and the signer may shorten this.
    pub max_expiration_seconds: i32,
}

impl PcrConfig {
    /// Build a [`PcrConfig`] from in-cluster defaults plus the supplied
    /// signer parameters.
    pub fn in_cluster(
        node_name: String,
        signer_name: String,
        trust_domain: String,
        max_expiration_seconds: i32,
    ) -> Result<Self, Error> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").map_err(|_| {
            Error::Spiffe("KUBERNETES_SERVICE_HOST not set; cannot use PCR provider".to_string())
        })?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS")
            .or_else(|_| std::env::var("KUBERNETES_SERVICE_PORT"))
            .unwrap_or_else(|_| "443".to_string());
        let apiserver_url = if host.contains(':') {
            format!("https://[{host}]:{port}")
        } else {
            format!("https://{host}:{port}")
        };
        Ok(Self {
            apiserver_url,
            ca_bundle_path: PathBuf::from(
                "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            ),
            token_path: PathBuf::from(
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
            ),
            node_name,
            signer_name,
            trust_domain,
            max_expiration_seconds,
        })
    }
}

type HttpsClient = LegacyClient<HttpsConnector<HttpConnector>, Full<bytes::Bytes>>;

/// CA client that mints workload certs via the Kubernetes
/// `PodCertificateRequest` API + constrained impersonation.
pub struct PcrCaClient {
    cfg: PcrConfig,
    client: HttpsClient,
}

impl PcrCaClient {
    pub async fn new(cfg: PcrConfig) -> Result<Self, Error> {
        let ca_pem = tokio::fs::read(&cfg.ca_bundle_path).await.map_err(|e| {
            Error::Spiffe(format!(
                "reading kube CA bundle {}: {e}",
                cfg.ca_bundle_path.display()
            ))
        })?;
        let mut roots = rustls::RootCertStore::empty();
        let mut cursor = std::io::Cursor::new(&ca_pem);
        for cert in rustls_pemfile::certs(&mut cursor) {
            let cert = cert.map_err(|e| Error::Spiffe(format!("parsing kube CA: {e}")))?;
            roots.add(cert).map_err(|e| {
                Error::Spiffe(format!("adding kube CA cert to store: {e}"))
            })?;
        }
        if roots.is_empty() {
            return Err(Error::Spiffe(
                "no trusted CA certificates found in kube CA bundle".to_string(),
            ));
        }

        let tls = ClientConfig::builder_with_provider(crypto_provider())
            .with_protocol_versions(tls::tls_versions())
            .map_err(|e| Error::Spiffe(format!("rustls config: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();

        let mut http = HttpConnector::new();
        http.set_connect_timeout(Some(Duration::from_secs(5)));
        http.enforce_http(false);
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_only()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);
        let client: HttpsClient = LegacyClient::builder(TokioExecutor::new()).build(https);

        Ok(Self { cfg, client })
    }

    async fn read_token(&self) -> Result<String, Error> {
        let raw = tokio::fs::read(&self.cfg.token_path).await.map_err(|e| {
            Error::Spiffe(format!(
                "reading SA token {}: {e}",
                self.cfg.token_path.display()
            ))
        })?;
        let s = String::from_utf8(raw)
            .map_err(|e| Error::Spiffe(format!("SA token is not utf-8: {e}")))?;
        Ok(s.trim().to_string())
    }

    fn impersonate_user(&self) -> String {
        format!("system:node:{}", self.cfg.node_name)
    }

    async fn do_request(
        &self,
        method: hyper::Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(http::StatusCode, bytes::Bytes), Error> {
        let token = self.read_token().await?;
        let url = format!("{}{}", self.cfg.apiserver_url, path);
        let body_bytes = body.unwrap_or_default();
        let body_full = Full::new(bytes::Bytes::from(body_bytes));
        let req = Request::builder()
            .method(method)
            .uri(&url)
            .header(hyper::header::AUTHORIZATION, format!("Bearer {token}"))
            .header(hyper::header::ACCEPT, CONTENT_TYPE_JSON)
            .header(hyper::header::CONTENT_TYPE, CONTENT_TYPE_JSON)
            .header("Impersonate-User", self.impersonate_user())
            .body(body_full)
            .map_err(|e| Error::Spiffe(format!("building kube request: {e}")))?;
        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| Error::Spiffe(format!("kube request to {url}: {e}")))?;
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| Error::Spiffe(format!("reading kube response: {e}")))?
            .to_bytes();
        Ok((status, bytes))
    }

    async fn get_pod_for_identity(&self, id: &Identity) -> Result<PodMeta, Error> {
        let (ns, sa) = match id {
            Identity::Spiffe {
                namespace,
                service_account,
                ..
            } => (namespace.clone(), service_account.clone()),
        };
        // fieldSelector cannot select on spec.serviceAccountName, so we
        // narrow by node and namespace and filter SA in code.
        let path = format!(
            "/api/v1/namespaces/{ns}/pods?fieldSelector=spec.nodeName={}",
            urlencoding(&self.cfg.node_name)
        );
        let (status, body) = self.do_request(hyper::Method::GET, &path, None).await?;
        if !status.is_success() {
            return Err(Error::Spiffe(format!(
                "list pods on node {}: status {status}, body {}",
                self.cfg.node_name,
                String::from_utf8_lossy(&body)
            )));
        }
        let list: PodList = serde_json::from_slice(&body)
            .map_err(|e| Error::Spiffe(format!("parsing pod list: {e}")))?;
        for pod in list.items {
            let phase_ok = matches!(
                pod.status.phase.as_deref(),
                Some("Pending") | Some("Running")
            );
            let sa_match = pod.spec.service_account_name.as_deref() == Some(sa.as_ref());
            if phase_ok && sa_match {
                return Ok(PodMeta {
                    name: pod.metadata.name.unwrap_or_default(),
                    uid: pod.metadata.uid.unwrap_or_default(),
                    namespace: ns.to_string(),
                    service_account: sa.to_string(),
                });
            }
        }
        Err(Error::Spiffe(format!(
            "no Pending/Running pod with SA {sa} found in ns {ns} on node {}",
            self.cfg.node_name
        )))
    }

    async fn get_sa_uid(&self, ns: &str, sa: &str) -> Result<String, Error> {
        let path = format!("/api/v1/namespaces/{ns}/serviceaccounts/{sa}");
        let (status, body) = self.do_request(hyper::Method::GET, &path, None).await?;
        if !status.is_success() {
            return Err(Error::Spiffe(format!(
                "get sa {ns}/{sa}: status {status}, body {}",
                String::from_utf8_lossy(&body)
            )));
        }
        let obj: ObjectWithMeta = serde_json::from_slice(&body)
            .map_err(|e| Error::Spiffe(format!("parsing sa: {e}")))?;
        obj.metadata
            .uid
            .ok_or_else(|| Error::Spiffe(format!("sa {ns}/{sa} has no uid")))
    }

    async fn get_node_uid(&self, node: &str) -> Result<String, Error> {
        let path = format!("/api/v1/nodes/{node}");
        let (status, body) = self.do_request(hyper::Method::GET, &path, None).await?;
        if !status.is_success() {
            return Err(Error::Spiffe(format!(
                "get node {node}: status {status}, body {}",
                String::from_utf8_lossy(&body)
            )));
        }
        let obj: ObjectWithMeta = serde_json::from_slice(&body)
            .map_err(|e| Error::Spiffe(format!("parsing node: {e}")))?;
        obj.metadata
            .uid
            .ok_or_else(|| Error::Spiffe(format!("node {node} has no uid")))
    }

    async fn create_pcr(&self, body: &PcrCreate) -> Result<String, Error> {
        let ns = &body.metadata.namespace;
        let path = format!("{PCR_API_PREFIX}/namespaces/{ns}/podcertificaterequests");
        let buf = serde_json::to_vec(body)
            .map_err(|e| Error::Spiffe(format!("serialising PCR: {e}")))?;
        let (status, resp_body) = self.do_request(hyper::Method::POST, &path, Some(buf)).await?;
        if !status.is_success() {
            return Err(Error::Spiffe(format!(
                "create PCR ns={ns}: status {status}, body {}",
                String::from_utf8_lossy(&resp_body)
            )));
        }
        let created: PcrObject = serde_json::from_slice(&resp_body)
            .map_err(|e| Error::Spiffe(format!("parsing created PCR: {e}")))?;
        created
            .metadata
            .name
            .ok_or_else(|| Error::Spiffe("created PCR has no name".to_string()))
    }

    async fn poll_pcr(&self, ns: &str, name: &str) -> Result<String, Error> {
        let deadline = tokio::time::Instant::now() + POLL_TIMEOUT;
        let path = format!("{PCR_API_PREFIX}/namespaces/{ns}/podcertificaterequests/{name}");
        loop {
            let (status, body) = self.do_request(hyper::Method::GET, &path, None).await?;
            if !status.is_success() {
                return Err(Error::Spiffe(format!(
                    "get PCR {ns}/{name}: status {status}, body {}",
                    String::from_utf8_lossy(&body)
                )));
            }
            let pcr: PcrObject = serde_json::from_slice(&body)
                .map_err(|e| Error::Spiffe(format!("parsing PCR {ns}/{name}: {e}")))?;
            if let Some(status) = pcr.status.as_ref() {
                for cond in &status.conditions {
                    if cond.type_ == "Denied" {
                        return Err(Error::Spiffe(format!(
                            "PCR {ns}/{name} denied: {}",
                            cond.message.as_deref().unwrap_or("(no message)")
                        )));
                    }
                    if cond.type_ == "Failed" {
                        return Err(Error::Spiffe(format!(
                            "PCR {ns}/{name} failed: {}",
                            cond.message.as_deref().unwrap_or("(no message)")
                        )));
                    }
                }
                if !status.certificate_chain.is_empty() {
                    return Ok(status.certificate_chain.clone());
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Spiffe(format!(
                    "timed out waiting for PCR {ns}/{name} status"
                )));
            }
            sleep(POLL_INTERVAL).await;
        }
    }
}

#[async_trait]
impl crate::identity::CaClientTrait for PcrCaClient {
    #[instrument(skip_all, fields(id = %id))]
    async fn fetch_certificate(&self, id: &Identity) -> Result<tls::WorkloadCertificate, Error> {
        // Validate the requested identity is in our trust domain. The
        // signer will derive the SPIFFE URI from the PCR's namespace +
        // serviceAccountName fields, so identities for other trust
        // domains cannot be issued via this provider.
        let (req_td, req_ns, req_sa) = match id {
            Identity::Spiffe {
                trust_domain,
                namespace,
                service_account,
            } => (
                trust_domain.to_string(),
                namespace.to_string(),
                service_account.to_string(),
            ),
        };
        if req_td != self.cfg.trust_domain {
            return Err(Error::Spiffe(format!(
                "identity {id} not in PCR provider trust domain {}",
                self.cfg.trust_domain
            )));
        }

        // Locate a real pod with this identity on the local node so the
        // PCR's spec carries valid pod/node UIDs that noderestriction
        // admission can verify.
        let pod = self.get_pod_for_identity(id).await?;
        debug!(pod = %pod.name, uid = %pod.uid, "selected pod for PCR");

        let sa_uid = self.get_sa_uid(&pod.namespace, &pod.service_account).await?;
        let node_uid = self.get_node_uid(&self.cfg.node_name).await?;

        // Generate the keypair, CSR, and proof-of-possession together so
        // they all reference the same public key (apiserver re-derives
        // it from PKIXPublicKey to verify the PoP signature).
        let mats = tls::csr::generate_for_pcr(&id.to_string(), pod.uid.as_bytes())?;
        let stub_pkcs10_b64 =
            base64::engine::general_purpose::STANDARD.encode(&mats.csr_der);
        let pkix_pub_b64 =
            base64::engine::general_purpose::STANDARD.encode(&mats.pkix_public_key_der);
        let pop_b64 =
            base64::engine::general_purpose::STANDARD.encode(&mats.proof_of_possession);

        let pcr = PcrCreate {
            api_version: "certificates.k8s.io/v1beta1".to_string(),
            kind: "PodCertificateRequest".to_string(),
            metadata: PcrMeta {
                generate_name: "ztunnel-".to_string(),
                namespace: pod.namespace.clone(),
            },
            spec: PcrSpec {
                signer_name: self.cfg.signer_name.clone(),
                pod_name: pod.name.clone(),
                pod_uid: pod.uid.clone(),
                service_account_name: req_sa,
                service_account_uid: sa_uid,
                node_name: self.cfg.node_name.clone(),
                node_uid,
                max_expiration_seconds: self.cfg.max_expiration_seconds,
                pkix_public_key: pkix_pub_b64,
                proof_of_possession: pop_b64,
                stub_pkcs10_request: stub_pkcs10_b64,
            },
        };
        let name = self.create_pcr(&pcr).await?;
        debug!(pcr_name = %name, ns = %pod.namespace, "created PCR; waiting for status");
        let chain_pem = self.poll_pcr(&pod.namespace, &name).await?;

        let pems = split_pem_certs(&chain_pem);
        if pems.is_empty() {
            return Err(Error::EmptyResponse(id.clone()));
        }
        let leaf = pems[0].as_bytes();
        let chain: Vec<&[u8]> = if pems.len() > 1 {
            pems[1..].iter().map(|s| s.as_bytes()).collect()
        } else {
            warn!("PCR signer returned no chain certs for {id}; identity verification will fail");
            vec![]
        };
        let certs = tls::WorkloadCertificate::new(&mats.private_key_pem, leaf, chain)?;
        if certs.identity().as_ref() != Some(id) {
            return Err(Error::SanError(id.clone()));
        }
        // Avoid unused-warning for req_ns in the trust-domain check.
        let _ = req_ns;
        Ok(certs)
    }
}

#[derive(Debug)]
struct PodMeta {
    name: String,
    uid: String,
    namespace: String,
    service_account: String,
}

// ---- Minimal Kubernetes JSON types ------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ObjectMetaIn {
    name: Option<String>,
    namespace: Option<String>,
    uid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ObjectWithMeta {
    metadata: ObjectMetaIn,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PodSpecIn {
    #[serde(rename = "serviceAccountName")]
    service_account_name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PodStatusIn {
    phase: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PodIn {
    #[serde(default)]
    metadata: ObjectMetaIn,
    #[serde(default)]
    spec: PodSpecIn,
    #[serde(default)]
    status: PodStatusIn,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PodList {
    items: Vec<PodIn>,
}

#[derive(Debug, Serialize)]
struct PcrCreate {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    metadata: PcrMeta,
    spec: PcrSpec,
}

#[derive(Debug, Serialize)]
struct PcrMeta {
    #[serde(rename = "generateName")]
    generate_name: String,
    namespace: String,
}

#[derive(Debug, Serialize)]
struct PcrSpec {
    #[serde(rename = "signerName")]
    signer_name: String,
    #[serde(rename = "podName")]
    pod_name: String,
    #[serde(rename = "podUID")]
    pod_uid: String,
    #[serde(rename = "serviceAccountName")]
    service_account_name: String,
    #[serde(rename = "serviceAccountUID")]
    service_account_uid: String,
    #[serde(rename = "nodeName")]
    node_name: String,
    #[serde(rename = "nodeUID")]
    node_uid: String,
    // Per KEP-4317 v1beta1 the wire field is `expirationSeconds` even
    // though the Go field name is `MaxExpirationSeconds`.
    #[serde(rename = "maxExpirationSeconds")]
    max_expiration_seconds: i32,
    // The legacy v1beta1 fields are still required as of Kubernetes
    // 1.35; StubPKCS10Request is preferred from 1.36 onward but having
    // all three filled in keeps both versions happy.
    #[serde(rename = "pkixPublicKey")]
    pkix_public_key: String,
    #[serde(rename = "proofOfPossession")]
    proof_of_possession: String,
    #[serde(rename = "stubPKCS10Request")]
    stub_pkcs10_request: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PcrCondition {
    #[serde(rename = "type")]
    type_: String,
    status: Option<String>,
    reason: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PcrStatus {
    #[serde(rename = "certificateChain")]
    certificate_chain: String,
    conditions: Vec<PcrCondition>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PcrObject {
    metadata: ObjectMetaIn,
    status: Option<PcrStatus>,
}

// ---- helpers ----------------------------------------------------------

/// Minimal application/x-www-form-urlencoded value escape for path
/// query parameters. Avoids pulling in a separate URL-encoding crate.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

/// Split a PEM blob containing one or more `-----BEGIN CERTIFICATE-----`
/// blocks into individual PEM strings.
fn split_pem_certs(blob: &str) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = blob;
    while let Some(start) = rest.find(BEGIN) {
        let after_start = &rest[start..];
        if let Some(end_off) = after_start.find(END) {
            let block = &after_start[..end_off + END.len()];
            out.push(block.to_string());
            rest = &after_start[end_off + END.len()..];
        } else {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_escapes_special_chars() {
        assert_eq!(urlencoding("kind-worker"), "kind-worker");
        assert_eq!(urlencoding("a/b"), "a%2Fb");
        assert_eq!(urlencoding("ns space"), "ns%20space");
    }

    #[test]
    fn split_pem_certs_finds_multiple_blocks() {
        let blob = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\nignored junk\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        let parts = split_pem_certs(blob);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("AAA"));
        assert!(parts[1].contains("BBB"));
    }

    #[test]
    fn split_pem_certs_handles_empty() {
        assert!(split_pem_certs("").is_empty());
        assert!(split_pem_certs("not a cert").is_empty());
    }

    #[test]
    fn pcr_spec_serialises_with_kube_field_names() {
        let pcr = PcrCreate {
            api_version: "certificates.k8s.io/v1beta1".to_string(),
            kind: "PodCertificateRequest".to_string(),
            metadata: PcrMeta {
                generate_name: "ztunnel-".to_string(),
                namespace: "default".to_string(),
            },
            spec: PcrSpec {
                signer_name: "spiffe.istio.io/cluster.local".to_string(),
                pod_name: "p".to_string(),
                pod_uid: "u".to_string(),
                service_account_name: "sa".to_string(),
                service_account_uid: "sauid".to_string(),
                node_name: "n".to_string(),
                node_uid: "nuid".to_string(),
                max_expiration_seconds: 86400,
                pkix_public_key: "cGsxeA==".to_string(),
                proof_of_possession: "cG9w".to_string(),
                stub_pkcs10_request: "Y3Ny".to_string(),
            },
        };
        let v: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&pcr).unwrap()).unwrap();
        assert_eq!(v["apiVersion"], "certificates.k8s.io/v1beta1");
        assert_eq!(v["spec"]["signerName"], "spiffe.istio.io/cluster.local");
        assert_eq!(v["spec"]["podName"], "p");
        assert_eq!(v["spec"]["podUID"], "u");
        assert_eq!(v["spec"]["serviceAccountUID"], "sauid");
        assert_eq!(v["spec"]["nodeUID"], "nuid");
        assert_eq!(v["spec"]["maxExpirationSeconds"], 86400);
        assert_eq!(v["spec"]["pkixPublicKey"], "cGsxeA==");
        assert_eq!(v["spec"]["proofOfPossession"], "cG9w");
        assert_eq!(v["spec"]["stubPKCS10Request"], "Y3Ny");
    }
}
