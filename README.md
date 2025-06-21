# SHARP-256 Protocol

**S**wift **H**ash **A**ssurance **R**ust **P**rotocol

[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

High-performance file transfer protocol with BLAKE3 integrity verification and comprehensive NAT traversal support.

## Features

- 🚀 **High Performance**: 80-90% network bandwidth utilization
- 🔒 **Integrity Verification**: BLAKE3 hash verification for all data
- 📊 **Adaptive Optimization**: System of Automatic Optimization (SAO) for dynamic performance tuning
- 💾 **Resume Support**: Automatic resume after connection interruption
- 🖥️ **Dual Mode**: GUI and headless operation modes
- 🔐 **Optional Encryption**: TLS 1.3 support
- 📈 **Dynamic Adaptation**: Real-time network condition adjustment
- 🌐 **Advanced NAT Traversal**: 
  - RFC 8489 compliant STUN with MESSAGE-INTEGRITY-SHA256
  - UPnP IGD v2.0 with automatic port mapping
  - NAT-PMP/PCP support
  - UDP hole punching with multiple strategies
  - TURN relay fallback
  - Automatic protocol selection and fallback
- 🔄 **Network Resilience**: Automatic reconnection and network change detection

## Architecture

- **Block Size**: 256 KB data blocks
- **Batch System**: 5-50 packets per batch (dynamically adjusted)
- **Hashing**: BLAKE3 for maximum performance
- **Transport**: UDP with custom reliability layer
- **Fragmentation**: Automatic MTU/GSO detection up to 64 KB packets
- **NAT Traversal**: Multi-protocol with automatic fallback chain

## Requirements

- Rust 1.70 or higher
- Cargo
- For GUI: System GUI libraries (automatically handled by eframe)

## Installation

### Building from Source

```bash
# Clone repository
git clone https://github.com/your-repo/sharp-256
cd sharp-256

# Full build with all features (GUI + NAT traversal)
cargo build --release

# Headless build (no GUI)
cargo build --release --no-default-features --features nat-traversal

# With TLS encryption support
cargo build --release --features tls

# All features
cargo build --release --all-features
```

### Binary Installation

Pre-built binaries available for:
- Windows (x64, ARM64)
- Linux (x64, ARM64)
- macOS (Intel, Apple Silicon)

## Usage

### Sender

#### GUI Mode
```bash
# Launch GUI for file selection and transfer
./sharp-sender

# With specific receiver
./sharp-sender --receiver 192.168.1.100:5555
```

#### Headless Mode
```bash
# Basic transfer
./sharp-sender file.zip 192.168.1.100:5555

# With encryption
./sharp-sender file.zip 192.168.1.100:5555 --encrypt

# Specify local bind address
./sharp-sender file.zip 192.168.1.100:5555 --bind 0.0.0.0:5556

# Disable NAT traversal
./sharp-sender file.zip 192.168.1.100:5555 --no-nat

# Verbose logging
./sharp-sender file.zip 192.168.1.100:5555 --log-level debug
```

### Receiver

#### GUI Mode
```bash
# Launch GUI receiver
./sharp-receiver

# Specify output directory
./sharp-receiver --output ~/Downloads
```

#### Headless Mode
```bash
# Basic receiver
./sharp-receiver --headless

# Custom port and directory
./sharp-receiver --bind 0.0.0.0:7777 --output ~/Downloads --headless

# Disable NAT traversal
./sharp-receiver --no-nat --headless
```

### Relay Server (for symmetric NAT)

```bash
# Start relay server
./sharp-relay --bind 0.0.0.0:5556

# With custom port
./sharp-relay --bind 0.0.0.0:8888 --log-level info
```

## NAT Traversal

SHARP-256 automatically handles various network configurations:

| Sender NAT | Receiver NAT | Connection Method |
|------------|--------------|-------------------|
| Public IP | Any | Direct |
| Any | Public IP | Direct |
| NAT | NAT (same network) | Direct (local) |
| Full Cone | Any NAT | Direct + STUN |
| Restricted | Full/Restricted | Hole Punching |
| Port Restricted | Full/Restricted | Hole Punching |
| Symmetric | Non-Symmetric | Limited Hole Punching |
| Any | Any | Relay (fallback) |

### Automatic Features:
- **STUN Discovery**: Detects public IP and NAT type
- **UPnP/NAT-PMP/PCP**: Automatic port forwarding on supported routers
- **Hole Punching**: Multiple strategies including birthday paradox optimization
- **Smart Fallback**: Automatic protocol selection based on network conditions
- **Connection Monitoring**: Detects network changes and adapts

## Performance

Tested on various network conditions:

| Network Type | Speed | SHARP-256 Performance |
|--------------|-------|----------------------|
| LAN (1 Gbps) | 1000 Mbps | 850-900 Mbps |
| WAN (1 Gbps) | 1000 Mbps | 800-850 Mbps |
| Internet (100 Mbps) | 100 Mbps | 85-90 Mbps |
| 4G LTE | 50 Mbps | 42-45 Mbps |

### With Encryption (TLS 1.3):
- ~10-15% overhead compared to unencrypted transfer

## System of Automatic Optimization (SAO)

SAO dynamically adjusts transfer parameters based on:
- Round Trip Time (RTT)
- Packet loss rate
- Bandwidth utilization
- Network jitter

Formula: `score = (1 - loss_rate) * bandwidth_utilization * (1 / (1 + rtt/100))`

## File Integrity

Every transfer includes:
- Per-packet BLAKE3 hashes
- Per-batch hash verification
- Complete file BLAKE3 verification
- Automatic corruption detection and retransmission

## State Management

Transfer state is automatically saved for resume capability:
- **Windows**: `%APPDATA%\sharp-256\states\`
- **Linux**: `~/.local/share/sharp-256/states/`
- **macOS**: `~/Library/Application Support/sharp-256/states/`

## GUI Features

### Sender GUI
- Drag & drop file selection
- Real-time transfer progress
- Network status display
- Speed and ETA indicators
- Transfer history

### Receiver GUI  
- Incoming transfer notifications
- Accept/Reject dialogs
- Multi-transfer management
- Transfer history
- Network status monitoring

## Configuration

### Environment Variables
- `SHARP_LOG_LEVEL`: Set log level (trace/debug/info/warn/error)
- `SHARP_STATE_DIR`: Override state directory location
- `SHARP_NO_NAT`: Disable NAT traversal globally

### Advanced Options
See `sharp-sender --help` and `sharp-receiver --help` for all options.

## API Integration

```rust
use sharp_256::{Sender, Receiver, NatConfig};

// Custom NAT configuration
let nat_config = NatConfig {
    enable_upnp: true,
    enable_stun: true,
    stun_servers: vec!["stun.example.com:3478".to_string()],
    ..Default::default()
};

// Send file with custom config
async fn send_file(file_path: &Path, receiver: SocketAddr) -> Result<()> {
    let sender = Sender::with_nat_config(
        "0.0.0.0:0".parse()?,
        receiver,
        file_path,
        false, // encryption
        nat_config,
    ).await?;
    
    sender.start_transfer().await?;
    Ok(())
}
```
```
// Example usage of SHARP3 with ICE

use SHARP3::{Sender, Receiver};
use std::path::Path;

// Sender side
async fn send_with_ice() -> anyhow::Result<()> {
    let file_path = Path::new("large_file.bin");
    
    // STUN servers for ICE
    let stun_servers = vec![
        "stun.l.google.com:19302".to_string(),
        "stun1.l.google.com:19302".to_string(),
        "stun.cloudflare.com:3478".to_string(),
    ];
    
    // Create sender with ICE
    // The peer_signaling_addr is used only for initial ICE parameter exchange
    let sender = Sender::new_with_ice(
        "receiver.example.com:5555".parse()?,
        file_path,
        true, // encryption
        stun_servers,
    ).await?;
    
    // ICE has already established the optimal path
    // Now just start the transfer
    sender.start_transfer().await?;
    
    Ok(())
}

// Receiver side
async fn receive_with_ice() -> anyhow::Result<()> {
    let output_dir = Path::new("./downloads");
    
    // Bind to signaling address
    let receiver = Receiver::new(
        "0.0.0.0:5555".parse()?,
        output_dir.to_path_buf(),
    ).await?;
    
    // Start with ICE support
    receiver.start_with_ice().await?;
    
    Ok(())
}
```

## Troubleshooting

### Common Issues

1. **"No route to host"**
   - Check firewall settings
   - Ensure receiver is listening
   - Verify IP addresses

2. **"NAT traversal failed"**
   - Enable UPnP on router
   - Check if symmetric NAT (use relay)
   - Try `--no-nat` for local networks

3. **Slow speeds**
   - Check network congestion
   - Verify no bandwidth limits
   - Try adjusting MTU detection

### Debug Mode

```bash
# Maximum verbosity
SHARP_LOG_LEVEL=trace ./sharp-sender file.zip 192.168.1.100:5555

# Log to file
./sharp-sender file.zip 192.168.1.100:5555 2> transfer.log
```

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Setup

```bash
# Install development dependencies
cargo install cargo-watch cargo-audit cargo-tarpaulin

# Run tests
cargo test

# Run with live reload
cargo watch -x run

# Check security advisories
cargo audit

# Generate coverage report
cargo tarpaulin --out Html
```

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Acknowledgments

- BLAKE3 team for the excellent hashing algorithm
- Rust async ecosystem contributors
- STUN/TURN protocol designers
- All contributors and testers

## Contact

- Issues: [GitHub Issues](https://github.com/your-repo/sharp-256/issues)
- Discussions: [GitHub Discussions](https://github.com/your-repo/sharp-256/discussions)
- Security: security@sharp256.dev
