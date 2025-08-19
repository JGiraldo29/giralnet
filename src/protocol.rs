use serde::{Serialize, Deserialize};
use std::net::SocketAddr;

pub type StreamID = u32;

#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakeMessage {
    pub encrypted_aes_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum CircuitMessage {
    BeginStream { id: StreamID, destination: SocketAddr },
    StreamData { id: StreamID, data: Vec<u8> },
    EndStream { id: StreamID },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum OnionLayer {
    Relay { next_hop: String, payload: Vec<u8> },
    Exit,
}