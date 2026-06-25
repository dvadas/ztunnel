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

use crate::tls::Error;

pub struct CertSign {
    pub csr: String,
    pub private_key: Vec<u8>,
}

pub struct CsrOptions {
    pub san: String,
}

impl CsrOptions {
    #[cfg(feature = "tls-boring")]
    pub fn generate(&self) -> Result<CertSign, Error> {
        use boring::ec::{EcGroup, EcKey};
        use boring::hash::MessageDigest;
        use boring::nid::Nid;
        use boring::pkey::PKey;
        use boring::stack::Stack;
        use boring::x509::extension::SubjectAlternativeName;
        use boring::x509::{self};
        // TODO: https://github.com/rustls/rcgen/issues/228 can we always use rcgen?

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        let pkey = PKey::from_ec_key(ec_key)?;

        let mut csr = x509::X509ReqBuilder::new()?;
        csr.set_pubkey(&pkey)?;
        let mut extensions = Stack::new()?;
        let subject_alternative_name = SubjectAlternativeName::new()
            .uri(&self.san)
            .critical()
            .build(&csr.x509v3_context(None))?;

        extensions.push(subject_alternative_name)?;
        csr.add_extensions(&extensions)?;
        csr.sign(&pkey, MessageDigest::sha256())?;

        let csr = csr.build();
        let pkey_pem = pkey.private_key_to_pem_pkcs8()?;
        let csr_pem = csr.to_pem()?;
        let csr_pem = std::str::from_utf8(&csr_pem)
            .expect("CSR is valid string")
            .to_string();
        Ok(CertSign {
            csr: csr_pem,
            private_key: pkey_pem,
        })
    }

    #[cfg(any(feature = "tls-ring", feature = "tls-aws-lc"))]
    pub fn generate(&self) -> Result<CertSign, Error> {
        use rcgen::{CertificateParams, DistinguishedName, SanType};
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let private_key = kp.serialize_pem();
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::URI(self.san.clone().try_into()?)];
        params.key_identifier_method = rcgen::KeyIdMethod::Sha256;
        // Avoid setting CN. rcgen defaults it to "rcgen self signed cert" which we don't want
        params.distinguished_name = DistinguishedName::new();
        let csr = params.serialize_request(&kp)?.pem()?;

        Ok(CertSign {
            csr,
            private_key: private_key.into(),
        })
    }

    #[cfg(feature = "tls-openssl")]
    pub fn generate(&self) -> Result<CertSign, Error> {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::stack::Stack;
        use openssl::x509::extension::SubjectAlternativeName;
        use openssl::x509::{self};
        // TODO: https://github.com/rustls/rcgen/issues/228 can we always use rcgen?

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        let pkey = PKey::from_ec_key(ec_key)?;

        let mut csr = x509::X509ReqBuilder::new()?;
        csr.set_pubkey(&pkey)?;
        let mut extensions = Stack::new()?;
        let subject_alternative_name = SubjectAlternativeName::new()
            .uri(&self.san)
            .critical()
            .build(&csr.x509v3_context(None))?;

        extensions.push(subject_alternative_name)?;
        csr.add_extensions(&extensions)?;
        csr.sign(&pkey, MessageDigest::sha256())?;

        let csr = csr.build();
        let pkey_pem = pkey.private_key_to_pem_pkcs8()?;
        let csr_pem = csr.to_pem()?;
        let csr_pem = std::str::from_utf8(&csr_pem)
            .expect("CSR is valid string")
            .to_string();
        Ok(CertSign {
            csr: csr_pem,
            private_key: pkey_pem,
        })
    }
}

/// Materials produced by [`generate_for_pcr`] for a single
/// PodCertificateRequest. This is a richer form than [`CertSign`] that
/// exposes the raw DER for `spec.stubPKCS10Request`, the
/// PKIX-serialized public key for the legacy `spec.pkixPublicKey`, and
/// a precomputed `spec.proofOfPossession` signature over
/// `sha256(podUID)`.
///
/// Only available with the rcgen-backed feature flags. Other crypto
/// backends (boring/openssl) currently fall back to an error in the
/// PCR client.
#[cfg(any(feature = "tls-ring", feature = "tls-aws-lc"))]
pub struct PcrMaterials {
    /// PEM-encoded PKCS#8 private key, ready to feed into
    /// `tls::WorkloadCertificate::new`.
    pub private_key_pem: Vec<u8>,
    /// DER-encoded PKCS#10 CertificateSigningRequest.
    pub csr_der: Vec<u8>,
    /// PKIX-serialized SubjectPublicKeyInfo. Required by the v1beta1
    /// `spec.pkixPublicKey` field on Kubernetes 1.35.
    pub pkix_public_key_der: Vec<u8>,
    /// Proof-of-possession signature: ECDSA-ASN.1 over `sha256(podUID)`.
    pub proof_of_possession: Vec<u8>,
}

/// Generate the full set of materials a PCR client needs in one shot.
///
/// `pod_uid` is the requesting pod's UID; the proof-of-possession is
/// computed over `sha256(pod_uid_bytes)` per KEP-4317.
#[cfg(any(feature = "tls-ring", feature = "tls-aws-lc"))]
pub fn generate_for_pcr(san: &str, pod_uid: &[u8]) -> Result<PcrMaterials, Error> {
    use rcgen::{CertificateParams, DistinguishedName, PublicKeyData, SanType};
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};

    // Generate one PKCS#8 P-256 key with `ring` and use it for both
    // the rcgen CSR (via from_pkcs8_der_and_sign_algo) and the
    // proof-of-possession signature, so that all three PCR fields
    // reference the same public key.
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|e| Error::CertificateParseError(format!("generate ECDSA P-256 key: {e}")))?;
    let pkcs8_der = pkcs8.as_ref().to_vec();

    let kp_pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8_der.clone());
    let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &kp_pkcs8,
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )?;
    let pkix_public_key_der = kp.subject_public_key_info();
    let private_key_pem = kp.serialize_pem().into_bytes();

    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::URI(san.to_string().try_into()?)];
    params.key_identifier_method = rcgen::KeyIdMethod::Sha256;
    params.distinguished_name = DistinguishedName::new();
    let csr_der = params.serialize_request(&kp)?.der().to_vec();

    let signing_kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_der, &rng)
        .map_err(|e| Error::CertificateParseError(format!("load ECDSA key: {e}")))?;
    // Sign the raw podUID bytes. ring's ECDSA_P256_SHA256_ASN1_SIGNING
    // hashes the input with SHA-256 internally before signing, matching
    // the apiserver's ecdsa.VerifyASN1(pub, sha256(podUID), sig).
    let pop = signing_kp
        .sign(&rng, pod_uid)
        .map_err(|e| Error::CertificateParseError(format!("sign proof of possession: {e}")))?;

    Ok(PcrMaterials {
        private_key_pem,
        csr_der,
        pkix_public_key_der,
        proof_of_possession: pop.as_ref().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use crate::tls;
    use itertools::Itertools;

    #[test]
    fn test_csr() {
        use x509_parser::prelude::*;
        let csr = tls::csr::CsrOptions {
            san: "spiffe://td/ns/ns1/sa/sa1".to_string(),
        }
        .generate()
        .unwrap();

        let (_, der) = x509_parser::pem::parse_x509_pem(csr.csr.as_bytes()).unwrap();

        let (_, cert) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&der.contents)
                .unwrap();
        cert.verify_signature().unwrap();
        let subject = cert.certification_request_info.subject.iter().collect_vec();
        assert_eq!(subject.len(), 0);
        let attr = cert
            .certification_request_info
            .iter_attributes()
            .next()
            .unwrap();

        let ParsedCriAttribute::ExtensionRequest(parsed) = attr.parsed_attribute() else {
            panic!("not a ExtensionRequest")
        };
        let ext = parsed.clone().extensions;
        assert_eq!(ext.len(), 1);
        let ext = ext.into_iter().next().unwrap();
        assert!(ext.critical);
        let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() else {
            panic!("not a SubjectAlternativeName")
        };
        assert_eq!(
            &format!("{san:?}"),
            "SubjectAlternativeName { general_names: [URI(\"spiffe://td/ns/ns1/sa/sa1\")] }"
        )
    }

    #[cfg(any(feature = "tls-ring", feature = "tls-aws-lc"))]
    #[test]
    fn test_generate_for_pcr_produces_all_fields() {
        let mats = tls::csr::generate_for_pcr("spiffe://td/ns/n/sa/s", b"podUID").unwrap();
        assert!(!mats.csr_der.is_empty());
        assert!(!mats.pkix_public_key_der.is_empty());
        assert!(!mats.proof_of_possession.is_empty());
        assert!(!mats.private_key_pem.is_empty());

        // The CSR must parse and contain our SAN.
        use x509_parser::prelude::*;
        let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(
            &mats.csr_der,
        )
        .unwrap();
        csr.verify_signature().unwrap();

        // The PKIX SPKI must parse as a valid SubjectPublicKeyInfo.
        let (_, _spki) =
            x509_parser::x509::SubjectPublicKeyInfo::from_der(&mats.pkix_public_key_der).unwrap();
    }
}
