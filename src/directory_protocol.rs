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

use rsa::RsaPublicKey;
use rsa::pkcs8::{EncodePublicKey, DecodePublicKey, LineEnding};
use serde::{Serialize, Deserialize};
use std::net::SocketAddr;

mod serde_rsa_public_key {
    use super::*;
    use serde::{Serializer, Deserializer};

    pub fn serialize<S>(key: &RsaPublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let pem = key.to_public_key_pem(LineEnding::LF).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&pem)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RsaPublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let pem = String::deserialize(deserializer)?;
        RsaPublicKey::from_public_key_pem(&pem).map_err(serde::de::Error::custom)
    }
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeInfo {
    pub address: SocketAddr,
    #[serde(with = "serde_rsa_public_key")]
    pub public_key: RsaPublicKey,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DirectoryRequest {
    Register {
        info: NodeInfo,
        secret: String,
    },

    GetNodes {
        secret: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DirectoryResponse {
    Ack,
    NodeList(Vec<NodeInfo>),
}