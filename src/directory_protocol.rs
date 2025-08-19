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