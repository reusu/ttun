# ttun

Minimal point-to-point TCP TUN tunnel. One server, one client, PSK authentication, AEAD obfuscation.

```
  ┌─────────────────┐    encrypted TCP    ┌─────────────────┐
  │     client      │ ──────────────────> │     server      │
  │  10.1.1.2/30    │ chacha20-poly1305 / │  10.1.1.1/30    │
  │  fc11::2/126    │ <─── aes-256-gcm ── │  fc11::1/126    │
  └────────┬────────┘                     └────────┬────────┘
           │                                       │
          TUN                                     TUN
```

## Design

- **Transport**: TCP only. `TCP_NODELAY` + 15s keepalive on both ends. Optional Multipath TCP (`-mptcp`) on Linux.
- **Topology**: strictly 1:1. The server accepts one peer; after handshake, the listener is idle until the peer disconnects. Other connection attempts block in the TCP backlog.
- **PSK auth**: `K = blake2s-256("ttun/psk/v1" || psk)`. Each side sends a 16-byte random nonce; both derive `SK = blake2s-256("ttun/sk/v1" || K || Nc || Ns)`. Each side then encrypts a fixed magic with `SK`; tag verification on the other side fails iff the PSK differs.
- **Wire frame**: `[u16 BE length][AEAD ciphertext+tag]`. Length covers ciphertext+tag (max 65535 → plaintext max 65519). Nonce = `dir(1B) || 0(3B) || counter(8B BE)`; directions differ between client→server and server→client so the two flows never share a nonce.
- **Cipher**: `chacha20-poly1305` (default) or `aes-256-gcm`. No Noise, no key exchange — just the PSK.
- **TUN device**: wireguard-go's `tun` package. Auto-named (`utunN` on darwin, first free `ttunN` on linux, `ttun`/`ttun<pid>` on windows).
- **Addresses are hard-coded** (dual-stack): server `10.1.1.1/30` + `fc11::1/126`, client `10.1.1.2/30` + `fc11::2/126`. No routes added — application traffic must target the tunnel IP directly, or you add your own routes.

## Build

```sh
./build.sh        # cross-compiles for darwin/linux/windows into ./build
go build ./...    # just the host
```

Windows runtime needs `wintun.dll` (download from <https://www.wintun.net> matching the EXE architecture) placed next to the binary.

## Usage

```sh
# server (needs root/admin for TUN)
sudo ./ttun server -k <psk>

# client
sudo ./ttun client -k <psk> -s <server-host>:20203

# AES-GCM instead of ChaCha20-Poly1305
sudo ./ttun server -k <psk> -m aes-256-gcm
sudo ./ttun client -k <psk> -s host:20203 -m aes-256-gcm

# force Multipath TCP (Linux)
sudo ./ttun server -k <psk> -mptcp
sudo ./ttun client -k <psk> -s host:20203 -mptcp
```

Flags:

| Flag | Default | Notes |
|---|---|---|
| `-m` | `chacha20-poly1305` | or `aes-256-gcm` |
| `-k` | (required) | preshared key (arbitrary string) |
| `-l` | `:20203` | server listen address |
| `-s` | — | client server `host:port` |
| `-mtu` | `1280` | TUN MTU |
| `-mptcp` | (unset) | force MPTCP on (`-mptcp`) or off (`-mptcp=false`); omit to keep the Go/system default |

### Multipath TCP

`-mptcp` sets `SetMultipathTCP` on the listener (server) and the dialer (client).
Only Linux implements MPTCP in Go; on darwin/windows the flag is accepted but the
connection stays plain TCP. Both ends must be MPTCP-capable — if the peer or a
middlebox does not support it, the kernel silently falls back to TCP. The log line
printed after each connection reports what was actually negotiated:

```
connected to host:20203 over mptcp; handshaking
```

Linux needs `sysctl -w net.mptcp.enabled=1` (default on since 5.6) and at least one
extra `mptcp` endpoint per host for a second subflow to be created, e.g.:

```sh
ip mptcp endpoint add 192.0.2.10 dev wlan0 subflow
ip mptcp limits set subflow 2 add_addr_accepted 2
```

Omitting the flag leaves Go's default (which enables MPTCP for listeners on Linux)
and any `GODEBUG=multipathtcp=...` setting untouched; `-mptcp=false` forces plain TCP.

Smoke test (after both endpoints are up, from the client):

```sh
ping  10.1.1.1
ping6 fc11::1
```

## Limitations

- No UDP transport, no multiple clients, no IP allocation, no routes, no rate limit. By design.
- MPTCP is Linux-only and needs kernel-side endpoint configuration to actually use more than one path; the flag alone does not aggregate links.
- TCP-over-TCP: under packet loss expect head-of-line blocking; pick a conservative MTU.
- No replay window: each session derives a fresh `SK` from the handshake nonces, so cross-session replay is impossible. Within a session, monotonic AEAD counters prevent in-session replay.
