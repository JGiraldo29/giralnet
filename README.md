# GiralNet - A High-Trust, Encrypted Onion Router

![Version](https://img.shields.io/badge/version-0.0.1-blue)
![Status](https://img.shields.io/badge/status-stable-green)
![Language](https://img.shields.io/badge/language-Rust-red)

GiralNet is a private, high-trust onion routing network written in Rust. It focuses on providing a secure and performant communication layer for small, trusted groups, such as teams of journalists or activists. Unlike public, zero-trust networks like Tor, GiralNet's security model is built on the principle that every participant is personally known and vetted, creating a secure, self-contained ecosystem.

This is the first stable release (v0.0.1) that provides the full core functionality.

![screenshot](https://raw.githubusercontent.com/JGiraldo29/giralnet/refs/heads/main/1.png?token=GHSAT0AAAAAADJLEX2SMRSQ5QG26GU7DSP42FEIO7Q)

## GiralNet Key Features

-   **High-Trust Security Model**: Your safety comes from the fact that you personally know and trust every node operator in the network.
-   **Dynamic 3-Hop Circuits**: Traffic is routed through three randomly selected nodes, obscuring the path between the user and the destination.
-   **Secure Directory Authority**: A central server, protected by TLS and a shared secret, manages the list of trusted nodes.
-   **End-to-End Encryption**: Utilizes a multi-layered encryption approach (Onion Routing) for traffic and TLS for directory communication.
-   **User-Friendly TUI**: An interactive text-based interface for first-time setup, making it accessible to non-developers.
-   **Self-Contained**: The entire network infrastructure is controlled by your team, with no reliance on third-party services.

## Current Functionality

-   **Network Core**
    -   **Directory Server**: Manages node registration and distribution.
    -   **Node**: Relays encrypted traffic within the network.
    -   **Proxy**: A local SOCKS5 proxy that acts as the user's entry point to the GiralNet network.

-   **Security Features**
    -   TLS encryption for all communication with the Directory Server.
    -   AES-256-GCM and RSA for the onion encryption layers.
    -   Shared secret authentication for all directory interactions.
    -   Automatic, guided generation of self-signed TLS certificates for the Directory Server.

-   **Usability**
    -   Interactive, menu-driven setup for new users.
    -   Automatic creation of a `config.toml` file to save settings.
    -   "Double-click to run" support for Windows executables (no console window).
    -   Clear, user-friendly prompts and error messages.

## Building

```bash
# Clone this repository
# git clone <your-repository-url>
# cd giralnet

# Build the release executable
cargo build --release
```

## Building

The final executable will be located in `target/release/giralnet.exe`.

---

## Running GiralNet

GiralNet is designed to be run without command-line arguments. The first time you run the executable in a new folder, an interactive setup will guide you.

### Quick Start Guide

A full test requires **5 instances** of the application running in separate folders: 1 Directory, 3 Nodes, and 1 Proxy.

#### 1. Start the Directory Server

1.  Create a folder named `DIRECTORY-SERVER`.
2.  Copy `giralnet.exe` into it and run it.
3.  Follow the setup prompts:
    * Select `[1] Directory Server`.
    * Agree to generate the TLS certificates (`cert.pem` and `key.pem`).
    * Enter the server's public IP address (or `localhost:8000` for local testing).
    * Create a strong shared secret.
4.  Leave this instance running.

#### 2. Share the Certificate

Copy the `cert.pem` file (the public key) from the `DIRECTORY-SERVER` folder. You must **securely send this file** to all other team members.

#### 3. Start the Nodes

For each of the three nodes:

1.  Create a new folder (e.g., `NODE-1`).
2.  Copy `giralnet.exe` and the shared `cert.pem` file into it.
3.  Run the executable.
4.  Select `[2] Node`.
5.  Enter the Directory Server's address and the shared secret.
6.  Provide a unique listening port for each node (e.g., `127.0.0.1:9001`, `127.0.0.1:9002`, etc.).

#### 4. Start the Proxy

1.  Create a folder for your client.
2.  Copy `giralnet.exe` and the shared `cert.pem` into it.
3.  Run the executable.
4.  Select `[3] Proxy` and enter the Directory/secret info.

#### 5. Configure Your Browser

1.  Go to your web browser's network settings.
2.  Set the **SOCKS5 proxy** to `127.0.0.1` on port `9050`.
3.  You can now browse the internet through GiralNet.

---

## Contributing

GiralNet is an open-source project and welcomes contributions. Here are some areas where you can help:

### Core Features
* Implementing Pluggable Transports for censorship resistance.
* Adding a more robust logging system.
* Improving circuit-building logic.

### Documentation
* Improving code comments.
* Writing more detailed architecture documentation.
* Creating user guides for different platforms.

### Testing
* Adding unit and integration tests.
* Performance benchmarking.

### Contributing Guidelines
1.  Fork the repository.
2.  Create a feature branch.
3.  Write clean, documented code.
4.  Submit a pull request.

---

## Known Limitations

As this is the first stable release, there are known limitations to be aware of:

* **Not resilient to state-level traffic analysis** due to the small, private nature of the network.
* The Directory Server is a **single point of failure**.
* The security of the network is entirely dependent on the **trustworthiness of the node operators**.
* The `cert.pem` file must be shared securely **out-of-band**.

---

## Future Plans

* Implement Pluggable Transports to disguise traffic.
* Develop a simple Graphical User Interface (GUI).
* Create a more advanced logging and status monitoring system.
* Explore decentralized discovery methods as an alternative to the central directory.

---

## License

This project is licensed under the **GNU General Public License v2.0**. See the `LICENSE` file for details.

---

## Acknowledgments

* The Rust programming language and its vibrant community.
* All the creators and maintainers of the open-source libraries that made this project possible.

---

## ✉️ Contact

Juan Miguel Giraldo - `jgiraldo29@proton.me`

> **Note:** GiralNet is a tool designed for specific, high-trust use cases. Understand its threat model and limitations before deploying it for sensitive operations.
