# Bellbird

An experiment using Go post-quantum cryptography to build a self-hostable SOCKS5
proxy with timing jitter, dummy packet injection, and frame size normalization
to resist traffic analysis. The idea is inspired by the already existing
[Mullvad's DAITA](https://mullvad.net/en/blog/daita-defense-against-ai-guided-traffic-analysis).

## Disclaimer for software operators

> [!WARNING]
> Due to the nature of cybersecurity/privacy tools I have to give a disclaimer.
>
> This program was written with the intent of self-defense from mass
> surveillance, privacy is not inherently suspicious. Think about that the next
> time you close the door when you use the toilet.
>
> Also, this is meant for home networks or internal networks for small teams, if
> you decide to run a public relay you are on your own.

## How it works

```text
[app] ──SOCKS5──▶ [bell client 127.0.0.1:1080] ──PQC tunnel──▶ [bell relay] ──▶ [destination]
                          │
               jitter + dummy packets + padding
               controlled by policy.zy (hot-reload on SIGHUP)
```

Layers:

1. Key Exchange: ML-KEM-768 + X25519 hybrid (NIST FIPS 203)
2. Symmetric Encryption: AES-256-GCM, authenticated per frame
3. Key Derivation: HKDF-SHA256
4. Noise Policy: Zygomys Lisp Script, hot-reloadable

## Quick Start

```bash
# Generate your relay keypair
$ bell keygen --out relay
# -> relay.pub (share with clients)
# -> relay.key (keep secure, it's on the relay server)

# Start your relay
$ bell relay --key <path_to_dotkey_file> --listen :9001

# Start a client
$ bell client --relay <relay_reachable_ip:9001> --pubkey <path_to_dotpub_file> \
    --listen 127.0.0.1:1080 \
    --policy <path_to_policy_zyfile>

# Connect
$ curl --socks5 localhost:1080 https://urutau-ltd.org/
```

If you need to hot-reload your policy file without restarting run:
`kill -HUP $(pgrep '^bell$')`

The client listen default is `127.0.0.1:1080` (loopback only).

## Usage Guide

For practical deployment patterns (per-device, gateway/family network, multiple
relays, public Wi-Fi workflows), see:

- [docs/USAGE.md](./docs/USAGE.md)

## End-to-End Self Test

To demonstrate the full flow locally (SOCKS5 -> client -> relay -> destination):

```bash
$ make e2e
```

Or directly:

```bash
$ bell selftest
```

## Optional Relay Token Auth

Relay (server):

```bash
$ bell relay --key relay.key --listen :9001 --token "$(cat relay.token)"
```

Client:

```bash
$ bell client --relay <relay:9001> --pubkey relay.pub --listen 127.0.0.1:1080 --policy policy.zy \
    --token "$(cat relay.token)"
```

You can also use `--token-file <path>` on both commands.

Relay default hardening: local/loopback/link-local destinations are denied. Use
`--allow-local-targets` only for lab/testing scenarios.

## Installation

Install the CLI package directly:

```bash
$ go install codeberg.org/urutau-ltd/bellbird/cmd/bellbird@latest
```

That installation path produces a `bellbird` binary name by default.

Or build the short-name binary (`bell`) locally:

```bash
$ make build
```

## Local Podman Pipeline

For local, runner-less CI execution (Codeberg "to each on their own"):

```bash
# run lint/vet/tests + build in a container
$ make pipeline

# run only CI checks
$ make pipeline-ci

# run only build stage
$ make pipeline-build

# run only end-to-end check stage
$ make pipeline-e2e

# run verification suite (includes token positive/negative checks)
$ make pipeline-verify
```

Pipeline notes:

- Uses [Containerfile.ci](./Containerfile.ci)
- Caches modules/build output in `.cache/pipeline/`
- You can override image/tag via `PIPELINE_IMAGE=...`

## Verification Suite

For a local verification pass:

```bash
$ make verify
```

This runs:

- unit/integration test suite (`make ci`)
- full e2e check (`bell selftest`)
- token-authenticated e2e
- negative auth check (expected failure with wrong token)

### Threat model

Protects against:

- Traffic correlation by timing.
- Payload fingerprinting by size.
- Burst pattern analysis.
- Passive quantum-capable global threat actors recording traffic today (HNDL).

These protections will fail if:

- A threat actor gains access to both endpoints
- You connect to a relay operated by a threat actor

For application-layer traffic you are on your own measures.

This is not Tor, it has "one hop" and no onion routing was taken in mind.
Combine with either Tor, I2P or a trustable VPN service for stronger privacy.

## Using as a Go package

Almost all pieces are importable:

```go
import "codeberg.org/urutau-ltd/bellbird/client"
import "codeberg.org/urutau-ltd/bellbird/relay"
import "codeberg.org/urutau-ltd/bellbird/pqc"
import "codeberg.org/urutau-ltd/bellbird/proxy"
```

## Further reading

This repository is published alongside a blog entry from our part. If you're
interested in reading more go to our website at https://urutau-ltd.org/
