# Xray-ProxyShaper

Integration of ProxyShaper into [Xray-core](https://github.com/XTLS/Xray-core), adding censorship-resistant traffic obfuscation capabilities to VLESS and VMess over TLS/uTLS.

## Overview

**Xray-ProxyShaper** extends Xray-core with ProxyShaper's bootstrap traffic shaping mode. For TCP + TLS/uTLS connections, ProxyShaper sits **after** the TLS handshake and **before** the proxy protocol handshake, shaping the first encrypted TLS application-data records to evade traffic analysis.

### Supported Protocols
- **Proxy Protocols**: VLESS, VMess
- **Transport**: TCP with TLS or uTLS
- **ProxyShaper Mode**: Bootstrap (TLS-derived)

## How It Works

### Bootstrap Workflow

1. **TLS Handshake** — Xray completes the outer TLS/uTLS handshake
2. **Derive Seed** — Both client and server independently derive a 64-bit seed from TLS exporter keying material using `ExportKeyingMaterial("proxyshaper-v1", nil, 8)`
3. **Select Row** — Bootstrap selects one valid 10-slot traffic pattern:
   - Generate 5 candidate rows from an external generator
   - Keep the first row that fits the negotiated TLS overhead
   - Retry with incremented seed if no row is valid
4. **Slot 0 Exchange** — The initiating side sends a slot 0 record containing:
   - 4-byte magic marker `PShp`
   - Optional proxy payload in remaining capacity
5. **Slot Execution** — Both peers execute slots 1-9 according to the derived schedule
6. **Return to Passthrough** — After slot 9, the connection returns to normal operation and proxy protocol proceeds

### Generated Flow Configuration

For `bootstrap + disableTiming` mode, traffic patterns are generated externally:

**Inputs:**
- `generatorPath` — Path to the obfs generator binary
- `trafficProfilePath` — Traffic profile file
- `modelPath` — Model assumptions JSON
- `numFlows` — Number of candidate rows to generate (typically 5)
- `flowLength` — Slots per row (typically 10)

**Behavior:**
- Derive initial seed from outer TLS exporter
- Run generator to produce candidate rows
- Both client and server independently select the same valid row using deterministic retry logic

### Slot Size Rules

Configured slot sizes represent **final encrypted TLS record size on the wire**, not plaintext bytes.

**Signed-size conventions:**
- Positive size = client → server
- Negative size = server → client
- Slot 0 must accommodate negotiated TLS overhead + 2-byte frame header + 4-byte marker

**Minimum on-wire sizes by cipher:**

| Cipher | TLS Version | Overhead | Slot 0 | Slots 1-9 |
|--------|-------------|----------|--------|-----------|
| AES-GCM | 1.2 | 29 | 35 | 31 |
| ChaCha20-Poly1305 | 1.2 | 21 | 27 | 23 |
| AEAD | 1.3 | 22 | 28 | 24 |

### Framing Format

**Slot 0 (with bootstrap marker):**
```
[4-byte magic: "PShp"][2-byte len][payload][random padding]
```

**Slots 1-9 (derived):**
```
[2-byte len][payload][random padding]
```

## Configuration Example

```json
{
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "proxyshaperSettings": {
      "mode": "bootstrap",
      "disableTiming": true,
      "generatedFlow": {
        "generatorPath": "/path/to/obfs",
        "trafficProfilePath": "/path/to/traffic_profile.bin",
        "modelPath": "/path/to/model_assumptions.json",
        "numFlows": 5,
        "flowLength": 10
      }
    }
  }
}
```

## Current Implementation

### Code Organization

- [`transport/internet/proxyshaper/`](transport/internet/proxyshaper/) — ProxyShaper integration into Xray transport layer
- [`transport/internet/tcp/dialer.go`](transport/internet/tcp/dialer.go) — Client-side ProxyShaper wrapping
- [`transport/internet/tcp/hub.go`](transport/internet/tcp/hub.go) — Server-side ProxyShaper wrapping
- [`transport/internet/tls/`](transport/internet/tls/) — TLS configuration and uTLS normalization
- [`proxyshaper/`](proxyshaper/) — External ProxyShaper host package (via `go.mod` replace)

## Compilation

### Requirements

- Go 1.21+

### Build Commands

**Linux / macOS:**
```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

**Windows (PowerShell):**
```powershell
$env:CGO_ENABLED=0
go build -o xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

**Reproducible Release:**
```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" \
  -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" -v ./main
```