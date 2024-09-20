# DNS Server in Rust

This project implements a basic DNS (Domain Name System) server using Rust. The goal is to build a fully functional DNS server that can resolve domain names to IP addresses while learning more about network programming in Rust.
<div float="left">
<img src="https://img.shields.io/github/license/ravikisha/RustDNS" alt="License" />
<img src="https://img.shields.io/github/stars/ravikisha/RustDNS" alt="Stars" />
<img src="https://img.shields.io/github/forks/ravikisha/RustDNS" alt="Forks" />
<img src="https://img.shields.io/github/issues/ravikisha/RustDNS" alt="Issues" />
<img src="https://img.shields.io/github/issues-pr/ravikisha/RustDNS" alt="Pull Requests" />
<img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust" />
<img src="https://img.shields.io/badge/OS-Linux-000000?style=for-the-badge&logo=linux&logoColor=white" alt="Linux" />
</div>

## Features

- Basic DNS query handling (A records)
- Multi-threaded server for handling multiple client requests
- Caching of DNS responses
- Custom configuration for DNS resolution
- Error handling and logging
- Support for both IPv4 and IPv6

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ravikisha/RustDNS.git
   cd rust-dns-server
   ```

2. **Install Rust** (if not already installed):
   Follow instructions from [rust-lang.org](https://www.rust-lang.org/tools/install).

3. **Build the project**:
   ```bash
   cargo build --release
   ```

## Usage

1. **Run the DNS server**:
   ```bash
   cargo run --release
   ```

2. **Query the DNS server**:
   You can use tools like `dig` to test the DNS server:
   ```bash
   dig @localhost example.com
   ```

3. **Configuration**:
   - The DNS server is configurable through a `config.toml` file, allowing you to define the upstream DNS servers, TTL, and other settings.

## Project Structure

- `src/main.rs`: Entry point of the server.

## Contributing

Feel free to fork this repository and submit pull requests. Contributions to improve features or add support for more DNS record types are welcome.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
