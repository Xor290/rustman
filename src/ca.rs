use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

pub struct Ca {
    cert: Certificate,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
    dir: PathBuf,
}

impl Ca {
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let dir = PathBuf::from(home).join(".rustman");
        std::fs::create_dir_all(&dir).ok();

        let cert = load_or_generate(&dir);
        Self {
            cert,
            cache: Mutex::new(HashMap::new()),
            dir,
        }
    }

    pub fn save_pem(&self) -> std::io::Result<PathBuf> {
        let path = self.dir.join("ca.crt");
        let pem = self
            .cert
            .serialize_pem()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&path, pem)?;
        Ok(path)
    }

    pub fn server_config_for(&self, host: &str) -> Arc<ServerConfig> {
        if let Some(c) = self.cache.lock().unwrap().get(host) {
            return c.clone();
        }

        let mut p = CertificateParams::new(vec![host.to_string()]);
        p.distinguished_name.push(DnType::CommonName, host);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        p.not_after = OffsetDateTime::now_utc() + Duration::days(825);

        let host_cert = Certificate::from_params(p).expect("host cert failed");
        let signed = host_cert
            .serialize_der_with_signer(&self.cert)
            .expect("signing failed");
        let key = host_cert.serialize_private_key_der();

        let cfg = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(signed)],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
                )
                .expect("ServerConfig failed"),
        );

        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), cfg.clone());
        cfg
    }
}

fn load_or_generate(dir: &Path) -> Certificate {
    let key_path = dir.join("ca.key");

    if let Ok(pem) = std::fs::read_to_string(&key_path) {
        if let Ok(kp) = KeyPair::from_pem(&pem) {
            match Certificate::from_params(ca_params(kp)) {
                Ok(cert) => {
                    eprintln!("[ca] loaded existing key from {}", key_path.display());
                    return cert;
                }
                Err(e) => eprintln!("[ca] warning: could not reconstruct cert from saved key: {e}"),
            }
        }
    }

    eprintln!("[ca] generating new CA key…");
    let kp = KeyPair::generate(&PKCS_ECDSA_P256_SHA256).expect("keygen failed");
    let pem = kp.serialize_pem();
    if let Err(e) = std::fs::write(&key_path, &pem) {
        eprintln!("[ca] warning: could not save key: {e}");
    }

    Certificate::from_params(ca_params(kp)).expect("CA cert generation failed")
}

fn ca_params(kp: KeyPair) -> CertificateParams {
    let mut p = CertificateParams::new(vec![]);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.distinguished_name
        .push(DnType::OrganizationName, "rustman");
    p.distinguished_name
        .push(DnType::CommonName, "rustman Proxy CA");
    p.not_before = OffsetDateTime::UNIX_EPOCH;
    p.not_after = OffsetDateTime::UNIX_EPOCH + Duration::days(36500);
    p.key_pair = Some(kp);
    p
}
