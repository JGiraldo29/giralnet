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

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use crate::{
    crypto,
    protocol::{CircuitMessage, HandshakeMessage, OnionLayer, StreamID},
    directory_protocol::{DirectoryRequest, DirectoryResponse, NodeInfo},
};
use std::collections::HashMap;
use std::error::Error;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use rsa::RsaPrivateKey;
use tokio::sync::mpsc;
use crate::tls_client;

pub async fn run(listen_addr: &str, key_file: &str, directory_server: Option<&str>, directory_secret: Option<&str>, ca_cert_path: Option<&str>) -> Result<(), Box<dyn Error>> {
    println!("[NODE] Starting on {}...", listen_addr);

    let private_key = crypto::generate_rsa_keys();
    let public_key = private_key.to_public_key();
    crypto::save_public_key(&public_key, &format!("{}.pub", key_file));
    println!("[NODE] Public key saved to {}.pub", key_file);

    if let Some(dir_addr) = directory_server {
        let secret = directory_secret.ok_or("Directory server specified, but --directory-secret is missing")?;
        let ca_path = ca_cert_path.ok_or("Directory server specified, but --ca-cert is missing")?;

        println!("[NODE] Registering securely with Directory Authority at {}...", dir_addr);
        
        let node_addr_str = format!("{}:{}", "127.0.0.1", listen_addr.split(':').last().unwrap());
        let mut addrs_iter = node_addr_str.to_socket_addrs()?;
        let node_addr = addrs_iter.next().ok_or("Could not resolve node address")?;

        let node_info = NodeInfo {
            address: node_addr,
            public_key: public_key.clone(),
        };
        
        let request = DirectoryRequest::Register {
            info: node_info,
            secret: secret.to_string(),
        };

        let mut stream = tls_client::connect(dir_addr, ca_path).await?;

        let req_bytes = bincode::serialize(&request)?;

        stream.write_u32(req_bytes.len() as u32).await?;
        stream.write_all(&req_bytes).await?;
        
        let res_len = stream.read_u32().await?;
        let mut res_buf = vec![0; res_len as usize];
        stream.read_exact(&mut res_buf).await?;

        let response: DirectoryResponse = bincode::deserialize(&res_buf)?;
        if let DirectoryResponse::Ack = response {
            println!("[NODE] Successfully registered with Directory Authority.");
        } else {
            eprintln!("[NODE] Failed to register with Directory Authority.");
        }
    }

    let listener = TcpListener::bind(listen_addr).await?;
    println!("[NODE] Listening for circuits...");
    loop {
        let (stream, _) = listener.accept().await?;
        let private_key_clone = private_key.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, private_key_clone).await {
                eprintln!("[NODE] Connection error: {}", e);
            }
        });
    }
}

async fn handle_connection(mut prev_hop_stream: TcpStream, private_key: RsaPrivateKey) -> Result<(), Box<dyn Error>> {
    let handshake_len = prev_hop_stream.read_u32().await?;
    let mut handshake_buf = vec![0; handshake_len as usize];
    prev_hop_stream.read_exact(&mut handshake_buf).await?;

    let handshake: HandshakeMessage = bincode::deserialize(&handshake_buf)?;
    let aes_key_bytes = crypto::rsa_decrypt(&private_key, &handshake.encrypted_aes_key);
    let session_key: [u8; 32] = aes_key_bytes.try_into()
        .map_err(|_| "Failed to convert session key to the correct size")?;
    println!("[NODE] Handshake successful.");

    let onion_len = prev_hop_stream.read_u32().await?;
    let mut onion_buf = vec![0; onion_len as usize];
    prev_hop_stream.read_exact(&mut onion_buf).await?;
    let (ciphertext, nonce) = onion_buf.split_at(onion_buf.len() - 12);
    let decrypted_payload = crypto::aes_decrypt(&session_key, nonce, ciphertext);
    let onion_layer: OnionLayer = bincode::deserialize(&decrypted_payload)?;

    match onion_layer {
        OnionLayer::Relay { next_hop, payload } => {
            println!("[NODE] Peeling onion. Forwarding to {}", next_hop);
            let mut next_stream = TcpStream::connect(next_hop).await?;
            next_stream.write_all(&payload).await?;
            println!("[NODE] Forwarded payload to next hop.");
            
            io::copy_bidirectional(&mut prev_hop_stream, &mut next_stream).await?;
        }
        OnionLayer::Exit => {
            println!("[NODE] >>> EXIT NODE REACHED <<<");
            
            let (mut reader, mut writer) = prev_hop_stream.into_split();
            let (tx, mut rx) = mpsc::channel::<CircuitMessage>(128);

            tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    let Ok(bytes) = bincode::serialize(&msg) else { continue };
                    let Ok(_) = writer.write_u32(bytes.len() as u32).await else { break };
                    if writer.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
            });

            let mut target_streams = HashMap::<StreamID, mpsc::Sender<Vec<u8>>>::new();
            loop {
                let msg_len = match reader.read_u32().await {
                    Ok(len) => len,
                    Err(_) => break,
                };
                let mut msg_buf = vec![0; msg_len as usize];
                if reader.read_exact(&mut msg_buf).await.is_err() {
                    break;
                }

                let circuit_msg: CircuitMessage = match bincode::deserialize(&msg_buf) {
                    Ok(msg) => msg,
                    Err(_) => continue,
                };

                match circuit_msg {
                    CircuitMessage::BeginStream { id, destination } => {
                        println!("[EXIT] New stream {} to {}", id, destination);
                        let tx_clone = tx.clone();
                        let (target_tx, mut target_rx) = mpsc::channel::<Vec<u8>>(128);
                        target_streams.insert(id, target_tx);

                        tokio::spawn(async move {
                            let target_stream = match TcpStream::connect(destination).await {
                                Ok(stream) => stream,
                                Err(e) => {
                                    eprintln!("[EXIT] Failed to connect to {}: {}", destination, e);
                                    let _ = tx_clone.send(CircuitMessage::EndStream { id }).await;
                                    return;
                                }
                            };
                            let (mut target_reader, mut target_writer) = target_stream.into_split();

                            let forward_task = tokio::spawn(async move {
                                while let Some(data) = target_rx.recv().await {
                                    if target_writer.write_all(&data).await.is_err() {
                                        break;
                                    }
                                }
                            });
                            
                            let mut read_buf = vec![0; 4096];
                            loop {
                                let n = match target_reader.read(&mut read_buf).await {
                                    Ok(n) if n > 0 => n,
                                    _ => break,
                                };
                                let data = read_buf[..n].to_vec();
                                if tx_clone.send(CircuitMessage::StreamData { id, data }).await.is_err() {
                                    break;
                                }
                            }
                            
                            forward_task.abort();
                            let _ = tx_clone.send(CircuitMessage::EndStream { id }).await;
                            println!("[EXIT] Closed stream {} to {}", id, destination);
                        });
                    }
                    CircuitMessage::StreamData { id, data } => {
                        if let Some(tx) = target_streams.get(&id) {
                            let _ = tx.send(data).await;
                        }
                    }
                    CircuitMessage::EndStream { id } => {
                        target_streams.remove(&id);
                        println!("[EXIT] Proxy requested to end stream {}", id);
                    }
                }
            }
        }
    }
    println!("[NODE] Connection closed.");
    Ok(())
}