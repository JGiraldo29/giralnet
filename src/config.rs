

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub mode: Mode,
    pub directory: DirectoryConfig,
    pub node: NodeConfig,
    pub proxy: ProxyConfig,
    pub tls: TlsConfig,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Mode {
    Directory,
    Node,
    Proxy,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectoryConfig {
    pub listen_addr: String,
    pub secret: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeConfig {
    pub listen_addr: String,
    pub key_file: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProxyConfig {
    pub listen_addr: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TlsConfig {
    pub ca_cert_path: String,
    pub cert_path: String,
    pub key_path: String,
}

pub fn load_config() -> Result<Config, Box<dyn Error>> {
    let config_str = fs::read_to_string("config.toml")?;
    let config: Config = toml::from_str(&config_str)?;
    Ok(config)
}