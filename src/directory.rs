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

use crate::directory_protocol::{DirectoryRequest, DirectoryResponse, NodeInfo};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

type NodeList = Arc<Mutex<HashMap<SocketAddr, NodeInfo>>>;

pub async fn run(listen_addr: &str, master_secret: &str, cert_path: &str, key_path: &str) -> Result<(), Box<dyn Error>> {
    println!("[DIR] Starting Directory Authority on {}...", listen_addr);

    let (certs, key) = load_certs_and_key(cert_path, key_path)?;
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let secret = master_secret.to_string();
    let nodes = Arc::new(Mutex::new(HashMap::new()));
    let listener = TcpListener::bind(listen_addr).await?;
    println!("[DIR] Listening for secure TLS connections...");

    loop {
        let (stream, addr) = listener.accept().await?;
        let acceptor_clone = acceptor.clone();
        let nodes_clone = nodes.clone();
        let secret_clone = secret.clone();

        tokio::spawn(async move {
            match acceptor_clone.accept(stream).await {
                Ok(tls_stream) => {
                    println!("[DIR] Accepted secure connection from {}", addr);
                    if let Err(e) = handle_connection(tls_stream, nodes_clone, secret_clone).await {
                        eprintln!("[DIR] Error handling connection from {}: {}", addr, e);
                    }
                }
                Err(e) => {
                    eprintln!("[DIR] TLS handshake error with {}: {}", addr, e);
                }
            }
        });
    }
}

async fn handle_connection<S>(mut stream: S, nodes: NodeList, master_secret: String) -> Result<(), Box<dyn Error>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let msg_len = stream.read_u32().await?;
    let mut msg_buf = vec![0; msg_len as usize];
    stream.read_exact(&mut msg_buf).await?;

    let request: DirectoryRequest = bincode::deserialize(&msg_buf)?;

    match request {
        DirectoryRequest::Register { info, secret } => {
            if secret != master_secret {
                eprintln!("[DIR] Denied registration from {} due to invalid secret.", info.address);
                return Ok(());
            }
            println!("[DIR] Received registration from node at {}", info.address);
            let mut nodes_lock = nodes.lock().await;
            nodes_lock.insert(info.address, info);
            let ack = bincode::serialize(&DirectoryResponse::Ack)?;
            stream.write_u32(ack.len() as u32).await?;
            stream.write_all(&ack).await?;
            println!("[DIR] Node registered. Total nodes: {}", nodes_lock.len());
        }
        DirectoryRequest::GetNodes { secret } => {
            if secret != master_secret {
                eprintln!("[DIR] Denied node list request due to invalid secret.");
                return Ok(());
            }
            println!("[DIR] Received request for node list.");
            let nodes_lock = nodes.lock().await;
            let node_list: Vec<NodeInfo> = nodes_lock.values().cloned().collect();
            let response = DirectoryResponse::NodeList(node_list);
            let res_bytes = bincode::serialize(&response)?;
            stream.write_u32(res_bytes.len() as u32).await?;
            stream.write_all(&res_bytes).await?;
            println!("[DIR] Sent list of {} nodes to proxy.", nodes_lock.len());
        }
    }
    Ok(())
}

fn load_certs_and_key(cert_path: &str, key_path: &str) -> Result<(Vec<Certificate>, PrivateKey), Box<dyn Error>> {
    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let certs = certs(&mut cert_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    let mut key_reader = BufReader::new(File::open(key_path)?);
    let mut keys = pkcs8_private_keys(&mut key_reader)?;

    if keys.len() != 1 {
        return Err("Expected a single private key".into());
    }
    Ok((certs, PrivateKey(keys.remove(0))))
}