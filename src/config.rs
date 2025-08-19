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