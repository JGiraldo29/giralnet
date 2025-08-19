use std::error::Error;
use std::fs;

pub fn generate_self_signed_cert() -> Result<(), Box<dyn Error>> {
    println!("[TLS SETUP] Generating self-signed certificate and private key...");

    let subject_alt_names = vec!["localhost".to_string()];

    let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;

    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.serialize_private_key_pem();

    fs::write("cert.pem", cert_pem.as_bytes())?;
    fs::write("key.pem", key_pem.as_bytes())?;

    println!("[TLS SETUP] Successfully generated cert.pem and key.pem");
    Ok(())
}