use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use tokio_rustls::rustls::ServerName;
use tokio_rustls::{TlsConnector, client::TlsStream};
use rustls_pemfile::certs;

pub async fn connect(addr: &str, ca_cert_path: &str) -> Result<TlsStream<TcpStream>, Box<dyn Error>> {
    let mut root_cert_store = RootCertStore::empty();
    let mut pem = BufReader::new(File::open(ca_cert_path)?);
    let certs = certs(&mut pem)?;
    
    let trust_anchors = certs.iter().map(|cert| {
        let ta = webpki::TrustAnchor::try_from_cert_der(cert).unwrap();
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    });
    
    root_cert_store.add_server_trust_anchors(trust_anchors);

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    
    let domain_str = addr.split(':').next().unwrap_or(addr);
    let domain = ServerName::try_from(domain_str)?;
    
    let stream = TcpStream::connect(addr).await?;
    let tls_stream = connector.connect(domain, stream).await?;

    Ok(tls_stream)
}