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

use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use crate::tls_client;

use crate::{
    crypto,
    protocol::{CircuitMessage, HandshakeMessage, OnionLayer, StreamID},
    directory_protocol::{DirectoryRequest, DirectoryResponse, NodeInfo},
};
use fast_socks5::{
    server::{Config, DenyAuthentication, Socks5Socket},
    Socks5Command as Command,
};
use rand::seq::SliceRandom;
use rsa::RsaPublicKey;


struct CircuitManager {
    tx: mpsc::Sender<CircuitMessage>,
    next_stream_id: AtomicU32,
}

impl CircuitManager {
    fn new(tx: mpsc::Sender<CircuitMessage>) -> Self {
        Self {
            tx,
            next_stream_id: AtomicU32::new(1),
        }
    }
    fn new_stream_id(&self) -> StreamID {
        self.next_stream_id.fetch_add(1, Ordering::SeqCst)
    }
}

pub async fn run(directory_addr: &str, directory_secret: &str, ca_cert_path: &str) -> Result<(), Box<dyn Error>> {
    println!("[PROXY] Starting SOCKS5 proxy...");

    let nodes = get_nodes_from_directory(directory_addr, directory_secret, ca_cert_path).await?;
    println!("[PROXY] Fetched {} nodes from directory.", nodes.len());

    if nodes.len() < 3 {
        return Err("Not enough nodes in directory to build a 3-hop circuit.".into());
    }

    println!("[PROXY] Establishing persistent circuit...");
    let circuit_stream = connect_to_circuit(nodes).await?;
    println!("[PROXY] Persistent circuit established.");

    let (mut circuit_reader, mut circuit_writer) = circuit_stream.into_split();
    let (tx, mut rx) = mpsc::channel::<CircuitMessage>(128);

    let browser_streams = Arc::new(Mutex::new(HashMap::<StreamID, mpsc::Sender<Vec<u8>>>::new()));

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Ok(bytes) = bincode::serialize(&msg) {
                if circuit_writer.write_u32(bytes.len() as u32).await.is_err() { break; }
                if circuit_writer.write_all(&bytes).await.is_err() { break; }
            }
        }
    });

    let browser_streams_clone = browser_streams.clone();
    tokio::spawn(async move {
        loop {
            let msg_len = match circuit_reader.read_u32().await {
                Ok(len) => len,
                Err(_) => break,
            };
            let mut msg_buf = vec![0; msg_len as usize];
            if circuit_reader.read_exact(&mut msg_buf).await.is_err() { break; }
            if let Ok(msg) = bincode::deserialize::<CircuitMessage>(&msg_buf) {
                let mut streams = browser_streams_clone.lock().await;
                match msg {
                    CircuitMessage::StreamData { id, data } => {
                        if let Some(tx) = streams.get(&id) {
                            let _ = tx.send(data).await;
                        }
                    }
                    CircuitMessage::EndStream { id } => {
                        streams.remove(&id);
                    }
                    _ => {}
                }
            }
        }
    });

    let circuit_manager = Arc::new(CircuitManager::new(tx));

    let listen_addr = "127.0.0.1:9050";
    let listener = TcpListener::bind(listen_addr).await?;
    println!("[PROXY] SOCKS5 proxy listening on {}. Configure your browser to use this address.", listen_addr);
    let socks_config = Arc::new(Config::<DenyAuthentication>::default());

    loop {
        let (inbound, addr) = listener.accept().await?;
        println!("[PROXY] Accepted browser connection from {}", addr);
        let server_socket = Socks5Socket::new(inbound, socks_config.clone());

        let manager_clone = circuit_manager.clone();
        let streams_clone = browser_streams.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_browser_connection(server_socket, manager_clone, streams_clone).await {
                eprintln!("[PROXY] Error during connection handling: {}", e);
            }
        });
    }
}

async fn get_nodes_from_directory(dir_addr: &str, secret: &str, ca_path: &str) -> Result<Vec<NodeInfo>, Box<dyn Error>> {
    println!("[PROXY] Connecting securely to directory server to fetch nodes...");

    let mut stream = tls_client::connect(dir_addr, ca_path).await?;
    println!("[PROXY] Connected to directory server to fetch nodes.");

    let request = DirectoryRequest::GetNodes {
        secret: secret.to_string(),
    };
    
    let req_bytes = bincode::serialize(&request)?;
    stream.write_u32(req_bytes.len() as u32).await?;
    stream.write_all(&req_bytes).await?;
    
    let res_len = stream.read_u32().await?;
    let mut res_buf = vec![0; res_len as usize];
    stream.read_exact(&mut res_buf).await?;
    
    let response: DirectoryResponse = bincode::deserialize(&res_buf)?;
    
    if let DirectoryResponse::NodeList(nodes) = response {
        Ok(nodes)
    } else {
        Err("Failed to get node list from directory".into())
    }
}

async fn handle_browser_connection(
    server_socket: Socks5Socket<TcpStream, DenyAuthentication>,
    manager: Arc<CircuitManager>,
    browser_streams: Arc<Mutex<HashMap<StreamID, mpsc::Sender<Vec<u8>>>>>,
) -> Result<(), Box<dyn Error>> {
    let mut browser_socket = server_socket.upgrade_to_socks5().await?;

    if browser_socket.cmd().as_ref() != Some(&Command::TCPConnect) {
        return Err("Only CONNECT command is supported".into());
    }

    let destination = browser_socket.target_addr().cloned().ok_or("Could not get target address")?;
    let destination_addr: SocketAddr = tokio::net::lookup_host(destination.to_string()).await?.next().ok_or("DNS resolution failed")?;

    let stream_id = manager.new_stream_id();
    println!("[PROXY] New stream {} to {}", stream_id, destination_addr);

    manager.tx.send(CircuitMessage::BeginStream { id: stream_id, destination: destination_addr }).await?;

    let (tx_to_browser, mut rx_from_circuit) = mpsc::channel::<Vec<u8>>(128);
    browser_streams.lock().await.insert(stream_id, tx_to_browser);
    
    let (mut browser_reader, mut browser_writer) = browser_socket.into_inner().into_split();
    
    let write_task = tokio::spawn(async move {
        while let Some(data) = rx_from_circuit.recv().await {
            if browser_writer.write_all(&data).await.is_err() { break; }
        }
    });

    let mut read_buf = vec![0; 4096];
    loop {
        let n = match browser_reader.read(&mut read_buf).await {
            Ok(n) if n > 0 => n,
            _ => break,
        };
        let data = read_buf[..n].to_vec();
        manager.tx.send(CircuitMessage::StreamData { id: stream_id, data }).await?;
    }

    let _ = manager.tx.send(CircuitMessage::EndStream { id: stream_id }).await;
    browser_streams.lock().await.remove(&stream_id);
    write_task.abort();
    println!("[PROXY] Closed stream {}", stream_id);
    Ok(())
}

async fn connect_to_circuit(mut available_nodes: Vec<NodeInfo>) -> Result<TcpStream, Box<dyn Error>> {
    let circuit_len = 3;
    if available_nodes.len() < circuit_len {
        return Err(format!("Not enough nodes to build a {}-hop circuit.", circuit_len).into());
    }

    let mut rng = rand::thread_rng();
    available_nodes.shuffle(&mut rng);
    let circuit_nodes: Vec<NodeInfo> = available_nodes.into_iter().take(circuit_len).collect();

    let node_addrs_str: Vec<String> = circuit_nodes.iter().map(|n| n.address.to_string()).collect();
    let node_keys: Vec<RsaPublicKey> = circuit_nodes.iter().map(|n| n.public_key.clone()).collect();
    
    println!("[PROXY] Building a dynamic {}-hop onion circuit via: {}", circuit_len, node_addrs_str.join(" -> "));

    let exit_layer = OnionLayer::Exit;
    let mut current_payload = bincode::serialize(&exit_layer)?;

    for i in (0..circuit_len - 1).rev() {
        let next_node_index = i + 1;
        let aes_key = crypto::generate_aes_key();
        let (ciphertext, nonce) = crypto::aes_encrypt(&aes_key, &current_payload);
        let mut encrypted_payload = ciphertext;
        encrypted_payload.extend_from_slice(&nonce);
        let handshake = HandshakeMessage {
            encrypted_aes_key: crypto::rsa_encrypt(&node_keys[next_node_index], &aes_key),
        };
        let serialized_handshake = bincode::serialize(&handshake)?;
        let mut new_payload_for_current_node = Vec::new();
        new_payload_for_current_node.extend_from_slice(&(serialized_handshake.len() as u32).to_be_bytes());
        new_payload_for_current_node.extend_from_slice(&serialized_handshake);
        new_payload_for_current_node.extend_from_slice(&(encrypted_payload.len() as u32).to_be_bytes());
        new_payload_for_current_node.extend_from_slice(&encrypted_payload);
        let relay_layer = OnionLayer::Relay {
            next_hop: node_addrs_str[next_node_index].clone(),
            payload: new_payload_for_current_node,
        };
        current_payload = bincode::serialize(&relay_layer)?;
    }

    let mut stream = TcpStream::connect(&node_addrs_str[0]).await?;
    let entry_aes_key = crypto::generate_aes_key();
    let entry_handshake = HandshakeMessage {
        encrypted_aes_key: crypto::rsa_encrypt(&node_keys[0], &entry_aes_key),
    };
    let serialized_handshake = bincode::serialize(&entry_handshake)?;
    let (ciphertext, nonce) = crypto::aes_encrypt(&entry_aes_key, &current_payload);
    let mut final_onion_payload = ciphertext;
    final_onion_payload.extend_from_slice(&nonce);
    stream.write_u32(serialized_handshake.len() as u32).await?;
    stream.write_all(&serialized_handshake).await?;
    stream.write_u32(final_onion_payload.len() as u32).await?;
    stream.write_all(&final_onion_payload).await?;
    
    Ok(stream)
}