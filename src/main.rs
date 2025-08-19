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

mod crypto;
mod protocol;
mod node;
mod proxy;
mod directory;
mod directory_protocol;
mod tls_setup;
mod tls_client;
mod config;
mod tui;

use config::{Config, Mode};
use std::error::Error;

#[tokio::main]
async fn main() {
    tui::show_splash_screen();

    let cfg = match config::load_config() {
        Ok(config) => config,
        Err(_) => {
            match tui::run_setup() {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Setup failed: {}. Exiting.", e);
                    return;
                }
            }
        }
    };

    println!("[LAUNCHER] Starting Giraldo Network in {:?} mode...", cfg.mode);
    
    let result: Result<(), Box<dyn Error>> = match cfg.mode {
        Mode::Directory => {
            directory::run(
                &cfg.directory.listen_addr,
                &cfg.directory.secret,
                &cfg.tls.cert_path,
                &cfg.tls.key_path,
            ).await
        }
        Mode::Node => {
            let dir_server = Some(cfg.directory.listen_addr.as_str());
            let dir_secret = Some(cfg.directory.secret.as_str());
            let ca_cert = Some(cfg.tls.ca_cert_path.as_str());

            node::run(
                &cfg.node.listen_addr,
                &cfg.node.key_file,
                dir_server,
                dir_secret,
                ca_cert,
            ).await
        }
        Mode::Proxy => {
            proxy::run(
                &cfg.directory.listen_addr,
                &cfg.directory.secret,
                &cfg.tls.ca_cert_path,
            ).await
        }
    };

    if let Err(e) = result {
        eprintln!("\n--- A critical error occurred ---");
        eprintln!("Error: {}", e);
        eprintln!("Press Enter to exit.");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
}