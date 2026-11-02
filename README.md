<div align="center">

# rsReticulum

**A Rust implementation of Reticulum.**


[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust 1.89+](https://img.shields.io/badge/rust-1.89%2B-orange.svg)](https://www.rust-lang.org)
[![Release baseline: Reticulum 1.4.2](https://img.shields.io/badge/release%20baseline-Reticulum%201.4.2-success.svg)](https://reticulum.network/)
[![Status](https://img.shields.io/badge/status-experimental-yellow.svg)](#compatibility-notes)

[Reticulum Manual](https://reticulum.network/manual/) |
[Ratspeak](https://github.com/ratspeak/Ratspeak) |
[rsLXMF](https://github.com/ratspeak/rsLXMF) |
[Reticulum](https://github.com/markqvist/Reticulum)

</div>

---

rsReticulum is a Rust implementation of Reticulum. This is not a fork of
Reticulum; it is Reticulum written in a different language, focused on staying
interoperable. It is not the source-of-truth implementation, do not treat it as one.

Commands are intentionally namespaced for Rust with `*-rs` command names, so
rsReticulum can live beside other Reticulum tools on `PATH` without worry.

## Contents

- [Build It](#build-it)
- [Rust API](api/README.md)
- [Tool Usage](#tool-usage)
- [Configuration](#configuration)
- [Interface Support](#interface-support)
- [Compatibility Notes](#compatibility-notes)
- [Contributing](#contributing)
- [License](#license)

## Build It

This guide describes the 1.4.0 source line at `5b38cae702a5b3984adf12a435f6d3012fcf90e1`, also used by Ratspeak 1.0.37. The published standalone tool download is [v1.3.0](https://github.com/ratspeak/rsReticulum/releases/tag/v1.3.0); use [its README](https://github.com/ratspeak/rsReticulum/blob/v1.3.0/README.md) and bundled `--help` for that build. A Cargo version in the current source is not a separate binary release.

From a new working directory:

```bash
git clone https://github.com/ratspeak/rsReticulum.git
git -C rsReticulum checkout --detach 5b38cae702a5b3984adf12a435f6d3012fcf90e1
cd rsReticulum
```

Run the build commands below from that directory. The host crates require Rust 1.89 or newer.

### macOS

Install Rust with `rustup`, then install Apple's command-line build tools:

```bash
xcode-select --install
```

Build the tools:

```bash
cargo build --release --locked
```

### Linux, Raspberry Pi, and VPS Hosts

Install Rust with `rustup`, then install the build packages:

Debian, Ubuntu, and Raspberry Pi OS:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config
```

Fedora:

```bash
sudo dnf install gcc make pkgconf-pkg-config
```

Arch:

```bash
sudo pacman -S --needed base-devel pkgconf
```

Build the tools:

```bash
cargo build --release --locked
```

### Windows

Install Rust with the MSVC toolchain. If Rust or Cargo asks for Visual Studio
Build Tools, install the "Desktop development with C++" workload.

Build from PowerShell:

```powershell
cargo build --release --locked
```

After the build, use the commands below with `./target/release/<tool>` on
macOS/Linux or `.\target\release\<tool>.exe` on Windows.

## Tool Usage

The `rns-tools` crate builds Rust-namespaced Reticulum utilities:

| Binary | Purpose |
| --- | --- |
| rnsd-rs | Shared Reticulum daemon. Owns interfaces and local control sockets. |
| rnstatus-rs | Interface, announce, path, link, and aggregate status. |
| rnpath-rs | Path lookup, path table inspection, rates, drops, and blackhole actions. |
| rnid-rs | Identity generation, inspection, public/private import/export, hashing, signing, verification, encryption, and decryption. |
| rnprobe-rs | Destination probe utility with loss and round-trip reporting. |
| rncp-rs | File transfer utility with send, listen, and authenticated fetch modes. |
| rnodeconf-rs | RNode inspection, EEPROM backup, and saved TNC/normal startup configuration. |
| rnsh-rs | Reticulum shell listener/client. |

Common command forms (use each binary’s `--help` for the complete option list):

```text
rnsd-rs     [-c CONFIG_DIR] [-v|-q]... [-i] [--service] [--exampleconfig] [--version]
rnstatus-rs [--all] [--sort rate|traffic|rx|tx|rxs|txs|announces|arx|atx|arxc|atxc|prx|ptx|prxc|ptxc|held|pvs|ivs|flt|txdrp|txdrb]
         [--reverse] [--announce-stats] [--link-stats] [--totals] [--json]
         [-d|--discovered] [-D] [-m [-I SECONDS]] [FILTER]
         [-R <transport_hash> -i <identity_file>]
rnpath-rs   [--table|--rates] [destination_hash] [--max HOPS]
rnpath-rs   <destination_hash>
rnprobe-rs  [-s SIZE] [-n COUNT] [-t TIMEOUT] [-w WAIT] [--json] <full_name> <destination_hash>
rnid-rs     [-i IDENTITY|-g FILE|-m PUB|-M PRV] [-p|-P] [-x|-X] [-H ASPECT]
            [-a [ASPECT]] [-e FILE|-d FILE|-s FILE|-V FILE] [-w FILE] [-f]
            [-R|-N] [-t SECONDS] [-b|-B] [--raw] [--version]
rncp-rs     <file> <destination_hash>
rncp-rs     -l [-b SECONDS] [-s DEST_DIR] [-a <allowed_hash>]...
rncp-rs     -l -F [-j <jail_dir>] [-a <allowed_hash>|-n]...
rncp-rs     -f <destination_hash> <remote_path> [-s DEST_DIR]
rnodeconf-rs [-i] [--config] [--eeprom-backup|--eeprom-dump] [--version] [PORT]
rnodeconf-rs -T --freq HZ --bw HZ --txp DBM --sf SF --cr CR PORT
rnodeconf-rs -N PORT
rnsh-rs     -l [-i FILE] [-s NAME] [-b PERIOD] [-a HASH]... [-n] [-A|-C] [-- CMD...]
rnsh-rs     [-i FILE] [-s NAME] [-N] [-m] [-w SECONDS] <destination_hash> [-- CMD...]
```

Add the release `bin/` directory or `target/release` to `PATH` if
you want to call them without a path prefix.

`rncp-rs` has a listener authorization limitation in both the current source
and standalone 1.3.0: `-a <hash>` and `allowed_identities` are checked when a
peer identifies, but identification is not required before receiving a pushed
file. Do not rely on the allowlist to exclude unidentified senders.

Without `-n`, fetch requests require an identified peer on the allowlist.
`rncp-rs -F` enables fetch service and leaves push reception enabled. Use
`-j <jail>` to constrain fetched paths to a directory under trusted local
control; it is not an operating-system sandbox.

`rnodeconf-rs` in both the current source and standalone 1.3.0 supports inspection,
EEPROM dump/backup, and saving TNC/normal startup settings. `-T` requires all five
RF values shown above. Firmware installation, signing/trust enrollment and
Bluetooth, Wi-Fi, display and interference-avoidance changes are disabled.
Their options remain in the parser but return an error.

`rnid-rs` tracks the Reticulum 1.4.2 identity utility surface for normal
software identities: public/private import and export, destination hashing,
`.pub` public identity files, and signed `.rsg` signature files. The
hardware-backed `rnid-rs hw` path is a Rust extension behind the `hardware`
feature and should still be treated as experimental.

Common `rnid-rs` flows for a POSIX shell. Replace uppercase placeholders with your values. Private exports and imported private data grant control of the identity; keep them out of shared terminals, logs and shell history.

```bash
# Generate and inspect an identity.
mkdir -p ~/.rsReticulum/identities
rnid-rs -g ~/.rsReticulum/identities/mgmt
rnid-rs -i ~/.rsReticulum/identities/mgmt -p
rnid-rs -i ~/.rsReticulum/identities/mgmt -H lxmf.delivery

# Export text identity material. -x is public, -X is private.
rnid-rs -i ~/.rsReticulum/identities/mgmt -x -b
rnid-rs -i ~/.rsReticulum/identities/mgmt -X -B

# Write identity files. Without -X, -w writes a public .pub file.
rnid-rs -i ~/.rsReticulum/identities/mgmt -w mgmt.pub
rnid-rs -i ~/.rsReticulum/identities/mgmt -X -w mgmt.rid
rnid-rs -m "PUBLIC_IDENTITY_DATA" -w peer.pub
rnid-rs -M "PRIVATE_IDENTITY_DATA" -X -w restored_identity

# Sign and validate. New signatures are Reticulum 1.4.2-compatible .rsg envelopes.
rnid-rs -i ~/.rsReticulum/identities/mgmt -s message.txt
rnid-rs -V message.txt.rsg
rnid-rs -i "SIGNER_IDENTITY_HASH" -N -V message.txt.rsg

# Encrypt to a public identity, decrypt with the matching private identity.
rnid-rs -i mgmt.pub -e message.txt
rnid-rs -i ~/.rsReticulum/identities/mgmt -d message.txt.rfe
```

Use `--raw -s <file>` only when a workflow intentionally needs the legacy raw
64-byte signature form. Normal `rnid-rs -s <file>` produces a `.rsg` file that
embeds the signer metadata needed for current and retained compatibility.

## Configuration

`rnsd-rs` reads Reticulum INI config from `<config-dir>/config`. If no config
directory is supplied, the default is:

| Platform | Default config file |
| --- | --- |
| Linux/macOS | `/etc/rsReticulum/config`, then `~/.config/rsReticulum/config`, then `~/.rsReticulum/config` |
| Windows | `%APPDATA%\rsReticulum\config` |

On Linux/macOS, the first two locations are selected only when their `config` file exists; otherwise the home-directory fallback is used.

Print the annotated starter configuration to standard output:

```bash
rnsd-rs --exampleconfig
```

Minimal TCP client example. Replace `reticulum.example.org` and the port with the endpoint supplied by your network operator:

```ini
[reticulum]
share_instance = yes
instance_control_socket = yes
enable_transport = no

[interfaces]

  [[Default TCP]]
    type = TCPClientInterface
    enabled = yes
    target_host = reticulum.example.org
    target_port = 4242
```

Review an imported Python or older Rust config before starting it. Each interface needs a supported type and an explicit `enabled = yes` or `interface_enabled = yes`. For an explicit IFAC size, use `ifac_size_unit = bits` with `ifac_size`, or the separate `ifac_size_bytes` key. Unmarked values from 1 to 64 are rejected as ambiguous; larger valid values are interpreted as bits. See the [configuration migration](api/migrations/capacity-and-receipts.md#explicit-ifac-units). The published 1.3.0 tools use the older byte convention. Keep unsupported interfaces disabled.

The default shared-instance data/control ports are `37428`/`37429`. Ratspeak
uses app-private `37430`/`37431` ports. If you run two daemons at the same
time, give one config a distinct port pair to avoid a port conflict:

```ini
[reticulum]
shared_instance_port = 37432
instance_control_port = 37433
```

Programs use the control port with the instance's RPC key: `rpc_key` under
`[reticulum]` when it is set, otherwise a key derived from the transport
identity. That key is an admin credential: a program that has it can read the
daemon's network state, drop its paths and block identities, so treat it like
a password and give it only to programs you trust.

## Interface Support

This stack is experimental. Include the source revision or binary version, platform, interface type and relevant logs when reporting a problem.

| Interface | Current behavior |
| --- | --- |
| TCP client/server | Config-backed IPv4 and IPv6 paths. |
| UDP | Unicast and IPv4 broadcast datagrams; this driver does not join multicast groups. |
| Auto | IPv6 multicast discovery with unicast UDP data on the local network. |
| Local shared instance | Config-backed TCP loopback or Unix socket depending on platform. |
| I2P | Config-backed SAM v3.1 path. |
| Pipe | Config-backed subprocess stdio pipe. |
| Backbone | Config-backed high-latency WAN-style tunnel. |
| Serial, KISS, RNode, RNode Multi, AX.25 KISS | Config-backed with the `serial` feature. |
| BLE RNode | Config-backed with the `ble` feature. |
| Bluetooth Peer | Runtime API used by Ratspeak. |
| Android USB-OTG | Runtime API for Android app embeddings. |
| Weave | Partial: interface driver implemented, not yet config-wired in the runtime. |
| Bluetooth Classic RFCOMM | Not implemented. |

## Established Link Routing

An initial Link Request uses normal Reticulum path discovery and may be
broadcast when no path is known. Once the responder accepts that request and
the initiator validates its proof, each local Link endpoint is bound to the
exact interface and role selected by the handshake. Later Link packets,
Channels, Resources, proofs, keepalives, and teardown never fall back to a
different path or interface; loss of the selected interface closes that Link.

Reliable Link control uses a bounded ordered queue, while realtime media has a
separate bounded best-effort path that cannot overtake retained control
traffic. A proof sent by the initiator uses its temporary signing key from
the Link Request; a proof sent by the responder uses the accepting destination
identity.

## Compatibility Notes

Most daemon and utility flows are implemented for the public `*-rs` tools:
`rnsd-rs`, `rnstatus-rs`, `rnpath-rs`, `rnid-rs`, `rnprobe-rs`, `rncp-rs`,
`rnsh-rs`, and `rnodeconf-rs`.

The standalone 1.3.0 release baseline is Python Reticulum 1.4.2. The complete byte-exact corpus,
utility vectors, source-truth oracles, and live Python interoperability matrix
are pinned to its exact source commit. Historical 1.3.8 audits and fixtures
retain their original provenance as backward-compatibility evidence. RNS 1.5.0
was not part of that complete release gate. The current source includes
selected later Python compatibility changes; those do not establish complete
parity with a later Python release.

Known gaps and intentional limits:

- `rnx`, `rnir`, `rnpkg`, `rngit`, and `git-remote-rns` are not implemented.
- `rnodeconf-rs` is partial; safe inspection/configuration and EEPROM
  dump/backup are furthest along. Firmware flashing, autoinstall/update, ROM
  bootstrap, destructive EEPROM wipe, and full signing-key management are not
  implemented.
- `rnstatus-rs` covers the practical operator surface, but does not implement
  every display/API behavior from upstream.
- `rnpath-rs` remote mode is read-only for table/rates, including destination
  filters, apart from the remote blackhole-list query path. Remote mutations
  and remote active path requests are full gaps.
- Interface discovery announces name this stack `rsRNS` and its version. Python
  Reticulum 1.5.5 and later auto-connects only to Backbone interfaces
  announced by Python Reticulum 1.5.2 or later, so a Python node auto-connects
  to an `rsRNS` interface only with `autoconnect_unverified_implementations =
  yes` in its `[reticulum]` section. `rnsd-rs` follows the same rule, and the
  same option lets it auto-connect to any announced Backbone interface.
- `rncp-rs` implements the listener `-b` announce interval. `-P/--phy-rates`
  is not supported.
- `rns-ratkey` hardware identity support is feature-gated and still has known
  hardware-verification gaps before it should be described as release-ready.

## Contributing

If the issue or contribution belongs upstream as well, start there. Python LXMF
and Reticulum remain the reference implementations.

PRs are closed for now until I have time to catch up on everything. I'm tired.

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE).
