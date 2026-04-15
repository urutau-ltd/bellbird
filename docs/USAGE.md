# Bellbird Usage Guide

This guide is for private deployments (home, family, friend group,
Tailscale/Netbird/Zerotier networks).

## 1. Choose your deployment shape

### Per-device client (recommended)

- Run `bell client` on each laptop/desktop/server device.
- Keep client bind on loopback: `--listen 127.0.0.1:1080`.
- Configure apps on that device to use SOCKS5 `127.0.0.1:1080`.

Pros:

- Best isolation per device.
- No shared local proxy port on LAN.

### Shared gateway client (family/home)

- Run one `bell client` on a trusted always-on host (mini-PC/router VM).
- Bind to LAN only if needed: `--listen <gateway_lan_ip>:1080`.
- Point selected apps/devices to that SOCKS5 endpoint.

Pros:

- Centralized maintenance.
- Good for devices where running `bell client` is inconvenient.

Cons:

- Gateway becomes a privacy/security choke point.

## 2. Bootstrap keys and token

On relay host:

```bash
bell keygen --out relay
```

Files created:

- `relay.pub` share with clients.
- `relay.key` keep only on relay host.

Optional but strongly recommended token auth:

```bash
printf '%s\n' 'replace-with-long-random-secret' > relay.token
chmod 600 relay.token
```

## 3. Start relay

```bash
bell relay --key relay.key --listen :9001 --token-file relay.token
```

Notes:

- Default hardening denies relay connections to local/loopback/link-local
  targets.
- `--allow-local-targets` is lab/testing only.

## 4. Start client

```bash
bell client \
  --relay <relay-host-or-ip>:9001 \
  --pubkey relay.pub \
  --policy policy.zy \
  --token-file relay.token \
  --listen 127.0.0.1:1080
```

Quick validation:

```bash
curl --socks5 127.0.0.1:1080 https://example.com
```

## 5. Connect applications/devices

Applications that support SOCKS5 can use Bellbird directly.

Examples:

```bash
curl --socks5 127.0.0.1:1080 https://example.com
git config --global http.proxy socks5://127.0.0.1:1080
ssh -o ProxyCommand='nc -x 127.0.0.1:1080 %h %p' host
```

Browser example (Firefox):

1. Settings -> Network Settings -> Manual proxy configuration.
2. SOCKS Host: `127.0.0.1`, Port: `1080`.
3. SOCKS v5, enable remote DNS in browser if available.

Phone/tablet note:

- Many mobile OSes do not provide a universal SOCKS5 system proxy.
- Use apps that support SOCKS5 directly, or route through a trusted gateway
  running `bell client`.

### Platform quick starts

#### Linux

- Keep `bell client` local: `--listen 127.0.0.1:1080`.
- CLI tools:
  - `curl --socks5 127.0.0.1:1080 ...`
  - `git config --global http.proxy socks5://127.0.0.1:1080`
  - `ssh -o ProxyCommand='nc -x 127.0.0.1:1080 %h %p' host`
- Browser: set SOCKS5 host `127.0.0.1`, port `1080`.

#### macOS

- Run `bell client` locally on the Mac.
- App-level (recommended): set SOCKS5 in browser/terminal tools directly.
- Per-network global proxy: System Settings -> Network -> Wi-Fi/Ethernet ->
  Details -> Proxies -> SOCKS Proxy (`127.0.0.1:1080`).

#### Windows

- Run `bell client` locally on Windows.
- Prefer app-level SOCKS5 settings (browser, git, ssh tooling).
- Windows system proxy settings are HTTP-oriented; SOCKS5 usually needs
  app-level configuration or an additional local gateway/proxy tool.

#### Android

- Stock Android Wi-Fi proxy UI is HTTP proxy, not SOCKS5.
- Practical options:
  - Use apps with native SOCKS5 support.
  - Use a trusted gateway on your network running `bell client` and route
    compatible apps through it.
  - Prefer overlay/private-network routing (Tailscale/Netbird/Zerotier) before
    using public networks.

#### iOS / iPadOS

- iOS Wi-Fi proxy settings are HTTP proxy, not SOCKS5.
- Practical options:
  - Use apps that support SOCKS5 directly.
  - Use a trusted gateway pattern (another device runs `bell client`, apps
    connect there when supported).
  - Keep token auth enabled for relay access.

## 6. Privacy topology patterns

### Pattern A: Home relay over private overlay (recommended)

- Client reaches relay through Tailscale/Netbird/Zerotier address.
- Relay is not internet-exposed.

### Pattern B: Travel/public Wi-Fi to home relay

- Connect device to overlay network first.
- Point Bellbird to overlay relay address.
- Keep token auth enabled.

### Pattern C: Two relays, two local profiles

Run two clients locally:

```bash
bell client --relay <relay-a>:9001 --pubkey relay-a.pub --token-file relay-a.token --listen 127.0.0.1:1080 --policy policy.zy
bell client --relay <relay-b>:9001 --pubkey relay-b.pub --token-file relay-b.token --listen 127.0.0.1:1081 --policy policy.zy
```

Then choose per app:

- Sensitive apps -> `127.0.0.1:1080`
- Regular apps -> `127.0.0.1:1081`

### Pattern D: Public relay endpoint (least preferred)

- Expose relay on internet only when private overlay routing is unavailable.
- Require token auth and strict host firewall.
- Rotate token if device loss/suspicion occurs.

## 7. Public Wi-Fi checklist

1. Join Wi-Fi and complete captive portal first.
2. Bring up private overlay network if used.
3. Start Bellbird client and verify with `curl --socks5`.
4. Use HTTPS-only services.
5. Treat network as hostile; avoid local LAN trust.

## 8. Operational hygiene

- Keep `relay.key` offline from clients and backups unless encrypted.
- Rotate tokens periodically.
- Keep Bellbird updated on relay and clients together.
- Run checks before upgrades:

```bash
make ci
make verify
```

## 9. Limits and expectations

- Bellbird is one-hop, not an anonymity network.
- Relay can see destination metadata.
- For stronger anonymity properties, combine with other systems by policy
  (accepting latency and complexity).
