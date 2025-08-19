use crate::config::{Config, Mode, DirectoryConfig, NodeConfig, ProxyConfig, TlsConfig};
use crate::tls_setup;
use dialoguer::{theme::ColorfulTheme, Select, Input, Confirm};
use std::error::Error;
use std::fs;
use std::path::Path;
use colored::*;

pub fn show_splash_screen() {
    print!("\x1B[2J\x1B[1;1H");

    let ascii_art = r#"
 #####  ### ######     #    #       #     # ####### ####### 
#     #  #  #     #   # #   #       ##    # #          #    
#        #  #     #  #   #  #       # #   # #          #    
#  ####  #  ######  #     # #       #  #  # #####      #    
#     #  #  #   #   ####### #       #   # # #          #    
#     #  #  #    #  #     # #       #    ## #          #    
 #####  ### #     # #     # ####### #     # #######    #    
"#;

    println!("{}", ascii_art.cyan().bold());

    println!("{}", "                      Version 0.0.1 ".truecolor(150, 150, 150));
    println!("\n{}\n", "             Developed by Juan Miguel Giraldo".bold());
    // println!("{}\n", "           Supported by the Migairu Corporation".italic());

    std::thread::sleep(std::time::Duration::from_secs(3));
}

pub fn run_setup() -> Result<Config, Box<dyn Error>> {
    println!("--- GiralNet v0.0.1 ---");
    println!("--- First-Time Setup ---\n");

    let theme = ColorfulTheme::default();

    let mode_selection = Select::with_theme(&theme)
        .with_prompt(" What is the primary role of this computer in the network?")
        .items(&[
            "[1] Directory Server (The central coordinator for the team)",
            "[2] Node (A relay that helps pass traffic)",
            "[3] Proxy (Your personal client for browsing)"
        ])
        .default(2)
        .interact()?;

    let mode = match mode_selection {
        0 => Mode::Directory,
        1 => Mode::Node,
        _ => Mode::Proxy,
    };

    if mode == Mode::Directory {
        if !Path::new("cert.pem").exists() || !Path::new("key.pem").exists() {
            println!("\nAs the Directory Server, this machine needs to create the master TLS certificates for the network.");
            let generate_certs = Confirm::with_theme(&theme)
                .with_prompt("Generate them now?")
                .default(true)
                .interact()?;
            
            if generate_certs {
                tls_setup::generate_self_signed_cert()?;
                println!("Success! 'cert.pem' and 'key.pem' have been created.");
                println!("IMPORTANT: You must securely send the 'cert.pem' file to every other member of your team.");
            } else {
                return Err("Directory Server cannot run without TLS certificates.".into());
            }
        }
    } else {
        if !Path::new("cert.pem").exists() {
            println!("\n--- Action Required ---");
            println!("To connect to the network, you need the 'cert.pem' file.");
            println!("Please get this file from the person running the Directory Server and place it in the same folder as this program.");
            println!("-----------------------");
            std::thread::sleep(std::time::Duration::from_secs(8));
            return Err("Cannot connect without the shared 'cert.pem' file.".into());
        }
    }

    println!("\nNow, let's configure the network settings.");

    let directory_addr: String = Input::with_theme(&theme)
        .with_prompt(" Enter the Directory Server's public address (e.g., 123.45.67.89:8000)")
        .default("localhost:8000".into())
        .interact_text()?;

    let secret: String = Input::with_theme(&theme)
        .with_prompt(" Enter the shared network secret (must be the same for all users)")
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.len() < 8 { Err("Secret must be at least 8 characters long.") } else { Ok(()) }
        })
        .interact_text()?;

    // --- NEW LOGIC TO HANDLE NODE ADDRESS ---
    let mut node_listen_addr = "127.0.0.1:9001".to_string();
    if mode == Mode::Node {
        node_listen_addr = Input::with_theme(&theme)
            .with_prompt(" Enter the local IP and port for this Node to listen on (e.g., 127.0.0.1:9001)")
            .with_initial_text(node_listen_addr)
            .interact_text()?;
    }
    // --- END NEW LOGIC ---
    
    let config = Config {
        mode,
        directory: DirectoryConfig {
            listen_addr: directory_addr,
            secret,
        },
        node: NodeConfig {
            listen_addr: node_listen_addr, // Use the new, configurable address
            key_file: "node_key".into(),
        },
        proxy: ProxyConfig {
            listen_addr: "127.0.0.1:9050".into(),
        },
        tls: TlsConfig {
            ca_cert_path: "cert.pem".into(),
            cert_path: "cert.pem".into(),
            key_path: "key.pem".into(),
        },
    };

    let config_str = toml::to_string_pretty(&config)?;
    fs::write("config.toml", config_str)?;

    println!("\n-------------------------------------");
    println!("Configuration saved to 'config.toml'!");
    println!("The application will now start...");
    println!("-------------------------------------\n");
    
    std::thread::sleep(std::time::Duration::from_secs(3));

    Ok(config)
}