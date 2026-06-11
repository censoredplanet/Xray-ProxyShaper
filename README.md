# Xray-ProxyShaper

Xray-ProxyShaper is an Xray-core fork with ProxyShaper wired into the TCP TLS/uTLS transport path.

It targets VLESS and VMess over TLS. After the outer TLS handshake finishes, but before the proxy protocol handshake starts, ProxyShaper modifies the packet size and order of the first 10 encrypted TLS application-data records. The rest of the connection is passed through normally.

## What It Does

ProxyShaper runs after TLS is established, so both peers can use the negotiated TLS session as shared state. Each side derives the same 64-bit seed with:

```text
ExportKeyingMaterial("proxyshaper-v1", nil, 8)
```

That seed drives the traffic-pattern generator (CensorKL:`https://github.com/censoredplanet/obfuscation`) to produce a list of signed packet sizes:

- Positive values are client-to-server records.
- Negative values are server-to-client records.
- Both peers run the same row-selection logic, so no seed has to be sent on the wire.

Once the row is selected, ProxyShaper shapes the first 10 TLS application-data records:

- Record 0 carries the `PShp` marker plus any proxy bytes already available.
- Records 1-9 follow the generated pattern.
- After record 9, the connection switches back to normal Xray passthrough.

Use it with VLESS or VMess over TCP with TLS/uTLS.

## Configuration

Add `proxyshaperSettings` under `streamSettings`:

```json
{
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "proxyshaperSettings": {
      "disableTiming": true,
      "generatedFlow": {
        "generatorPath": "/path/to/CensorKLBinary",
        "trafficProfilePath": "/path/to/traffic_profile.bin",
        "modelPath": "/path/to/model_assumptions.json",
        "numFlows": 5,
        "flowLength": 10
      }
    }
  }
}
```

The generated row uses final encrypted TLS record sizes, not plaintext payload sizes. ProxyShaper subtracts the negotiated TLS record overhead at runtime before framing proxy bytes.

Minimum generated sizes:

| Cipher | TLS Version | TLS overhead | Record 0 | Records 1-9 |
| --- | --- | ---: | ---: | ---: |
| AES-GCM | 1.2 | 29 | 35 | 31 |
| ChaCha20-Poly1305 | 1.2 | 21 | 27 | 23 |
| AEAD | 1.3 | 22 | 28 | 24 |

Frame layout:

```text
Record 0:     [4-byte magic "PShp"][2-byte len][payload][random padding]
Records 1-9: [2-byte len][payload][random padding]
```

## Repository Layout

- [`proxyshaper/`](proxyshaper/) contains the scheduler, TLS exporter seed derivation, framing, and generator integration.
- [`transport/internet/proxyshaper/`](transport/internet/proxyshaper/) adapts ProxyShaper into Xray's stream settings.
- [`transport/internet/tcp/dialer.go`](transport/internet/tcp/dialer.go) wraps outbound TCP TLS connections.
- [`transport/internet/tcp/hub.go`](transport/internet/tcp/hub.go) wraps inbound TCP TLS connections.
- [`transport/internet/tls/`](transport/internet/tls/) carries the TLS/uTLS record-sizing changes needed for stable one-write-one-record behavior.

## Build

Requires Go 1.26+.

Linux / macOS:

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

Windows PowerShell:

```powershell
$env:CGO_ENABLED=0
go build -o xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

Reproducible release-style build:

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" \
  -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" -v ./main
```
