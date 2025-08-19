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