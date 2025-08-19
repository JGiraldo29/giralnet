// Copyright 2025 Juan Miguel Giraldo
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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