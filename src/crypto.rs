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

use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rsa::pkcs8::{EncodePublicKey, DecodePublicKey, LineEnding};
use std::fs;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;

const RSA_BITS: usize = 2048;
const AES_KEY_SIZE: usize = 32;

pub fn generate_rsa_keys() -> RsaPrivateKey {
    RsaPrivateKey::new(&mut OsRng, RSA_BITS).expect("Failed to generate a key")
}

pub fn rsa_encrypt(pub_key: &RsaPublicKey, data: &[u8]) -> Vec<u8> {
    pub_key.encrypt(&mut OsRng, Pkcs1v15Encrypt, data).expect("Failed to encrypt")
}

pub fn rsa_decrypt(priv_key: &RsaPrivateKey, data: &[u8]) -> Vec<u8> {
    priv_key.decrypt(Pkcs1v15Encrypt, data).expect("Failed to decrypt")
}

pub fn generate_aes_key() -> [u8; AES_KEY_SIZE] {
    rand::random()
}

pub fn aes_encrypt(key: &[u8; AES_KEY_SIZE], data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, data.as_ref()).expect("AES encryption failed");
    (ciphertext, nonce_bytes.to_vec())
}

pub fn aes_decrypt(key: &[u8; AES_KEY_SIZE], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let nonce = Nonce::from_slice(nonce);

    cipher.decrypt(nonce, ciphertext.as_ref()).expect("AES decryption failed")
}

pub fn save_public_key(pub_key: &RsaPublicKey, file_path: &str) {
    let pem = pub_key.to_public_key_pem(LineEnding::LF).expect("Failed to encode public key");
    fs::write(file_path, pem).expect("Failed to write public key to file");
}

pub fn load_public_key(file_path: &str) -> RsaPublicKey {
    let pem = fs::read_to_string(file_path).expect("Failed to read public key from file");
    RsaPublicKey::from_public_key_pem(&pem).expect("Failed to decode public key")
}