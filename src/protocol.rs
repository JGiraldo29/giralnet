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