<div align="center">

# rsReticulum

**A Rust implementation of Reticulum.**


[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Compatibility floor: Reticulum 1.3.8](https://img.shields.io/badge/compatibility%20floor-Reticulum%201.3.8-success.svg)](https://reticulum.network/)
[![Current reference: Reticulum 1.4.2](https://img.shields.io/badge/current%20reference-Reticulum%201.4.2-blue.svg)](https://github.com/markqvist/Reticulum)
[![Status](https://img.shields.io/badge/status-experimental-yellow.svg)](#feature-status)

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
- [Tool Usage](#tool-usage)
- [Configuration](#configuration)
- [Interface Support](#interface-support)
- [Compatibility Notes](#compatibility-notes)
- [Contributing](#contributing)
- [License](#license)

## Build It

### macOS

Install Rust with `rustup`, then install Apple's command-line build tools:

```bash
xcode-select --install
```

Build the tools:

```bash
cd rsReticulum
cargo build --release
```

### Linux, Raspberry Pi, and VPS Hosts

##### Install Rust with `rustup`, then install the needed packages:

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

##### Build the tools:

```bash
cd rsReticulum
cargo build --release
```

### Windows

Install Rust with the MSVC toolchain. If Rust or Cargo asks for Visual Studio
Build Tools, install the "Desktop development with C++" workload.

Build from PowerShell:

```powershell
cd rsReticulum
cargo build --release
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
| rnodeconf-rs | RNode inspection, safe configuration, EEPROM backup, and trust utility. |
| rnsh-rs | Reticulum shell listener/client. |

#### Commands:

```text
rnsd-rs     [-c CONFIG_DIR] [-v|-q]... [-i] [--service] [--exampleconfig] [--version]
rnstatus-rs [--all] [--sort rate|traffic|rx|tx|rxs|txs|announces|arx|atx|prx|ptx|held]
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
rnodeconf-rs [-i] [-N|-T] [-b|-B|-p] [-w MODE] [-D N] [-t N] [-R N] [--freq HZ]
            [--bw HZ] [--txp DBM] [--sf SF] [--cr CR] [-x|-X]
            [--eeprom-backup|--eeprom-dump] [--trust-key HASH] [--version] [PORT]
rnsh-rs     -l [-i FILE] [-s NAME] [-b PERIOD] [-a HASH]... [-n] [-A|-C] [-- CMD...]
rnsh-rs     [-i FILE] [-s NAME] [-N] [-m] [-w SECONDS] <destination_hash> [-- CMD...]
```

Add the release `bin/` directory or `target/release` to `PATH` if
you want to call them without a path prefix.

`rncp-rs` follows the established listener authentication model: without `-n`,
incoming senders must match `-a <hash>` or an `allowed_identities` file.
`rncp-rs -F` can serve fetch requests to authenticated clients; use
`-j <jail>` to bound file access unless unrestricted fetch paths are
intentional.

`rnodeconf-rs` in the current build only covers safe inspection/device setting paths, EEPROM
dump/backup, and trusted-key storage.

`rnid-rs` tracks the Reticulum 1.3.8 identity utility surface for normal
software identities: public/private import and export, destination hashing,
`.pub` public identity files, and signed `.rsg` signature files. The
hardware-backed `rnid-rs hw` path is a Rust extension behind the `hardware`
feature and should still be treated as experimental.

Common `rnid-rs` flows:

```bash
# Generate and inspect an identity.
rnid-rs -g ~/.rsReticulum/identities/mgmt
rnid-rs -i ~/.rsReticulum/identities/mgmt -p
rnid-rs -i ~/.rsReticulum/identities/mgmt -H lxmf.delivery

# Export text identity material. -x is public, -X is private.
rnid-rs -i ~/.rsReticulum/identities/mgmt -x -b
rnid-rs -i ~/.rsReticulum/identities/mgmt -X -B

# Write identity files. Without -X, -w writes a public .pub file.
rnid-rs -i ~/.rsReticulum/identities/mgmt -w mgmt.pub
rnid-rs -i ~/.rsReticulum/identities/mgmt -X -w mgmt.rid
rnid-rs -m <public_identity_data> -w peer.pub
rnid-rs -M <private_identity_data> -X -w restored_identity

# Sign and validate. New signatures are Reticulum 1.3.8 .rsg envelopes.
rnid-rs -i ~/.rsReticulum/identities/mgmt -s message.txt
rnid-rs -V message.txt.rsg
rnid-rs -i <signer_hash> -N -V message.txt.rsg

# Encrypt to a public identity, decrypt with the matching private identity.
rnid-rs -i mgmt.pub -e message.txt
rnid-rs -i ~/.rsReticulum/identities/mgmt -d message.txt.rfe
```

Use `--raw -s <file>` only when a workflow intentionally needs the legacy raw
64-byte signature form. Normal `rnid-rs -s <file>` produces a `.rsg` file that
embeds the signer metadata needed for 1.3.8 validation.

## Configuration

`rnsd-rs` reads Reticulum INI config from `<config-dir>/config`. If no config
directory is supplied, the default is:

| Platform | Default config file |
| --- | --- |
| Linux/macOS | `/etc/rsReticulum/config`, then `~/.config/rsReticulum/config`, then `~/.rsReticulum/config` |
| Windows | `%APPDATA%\rsReticulum\config` |

Generate the annotated starter file:

```bash
rnsd-rs --exampleconfig
```

Minimal TCP client example:

```ini
[reticulum]
share_instance = yes
instance_control_socket = yes
enable_transport = no

[interfaces]

  [[Default TCP]]
    type = TCPClientInterface
    enabled = yes
    target_host = rns.ratspeak.org
    target_port = 4242
```

Existing Python Reticulum configs should work if every requested interface
is implemented here. Unknown or not-yet-wired interfaces should be removed or
disabled until support lands.

The default shared-instance data/control ports are `37428`/`37429`. Ratspeak
uses app-private `37430`/`37431` ports. If you run two daemons at the same
time, give one config a distinct port pair to avoid confliction, like:

```ini
[reticulum]
shared_instance_port = 37432
instance_control_port = 37433
```

## Interface Support

###### Note: This is alpha, if something doesn't work, open an issue with enough context/information to help contribute to fixing it.

| Interface | Current behavior |
| --- | --- |
| TCP client/server | Config-backed IPv4 and IPv6 paths. |
| UDP | Config-backed unicast and multicast paths. |
| Auto | Config-backed UDP discovery plus TCP fallback. |
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
traffic. Initiator packet proofs use the temporary signing key advertised in
the Link Request, and responder packet proofs use the accepting destination
identity.

## Compatibility Notes

Most daemon and utility flows are implemented for the public `*-rs` tools:
`rnsd-rs`, `rnstatus-rs`, `rnpath-rs`, `rnid-rs`, `rnprobe-rs`, `rncp-rs`,
`rnsh-rs`, and `rnodeconf-rs`.

The compatibility floor is Reticulum 1.3.8 where the matching Rust surface is
implemented and tested, including version-specific utility and byte-exact
fixtures. Current protocol and daemon behavior is also audited and
interoperability-tested against Reticulum 1.4.2. The older corpus remains
deliberate backward-compatibility evidence rather than a claim that 1.3.8 is
the newest upstream. `rnid-rs` has explicit 1.3.8 coverage for the normal
identity utility flow.

Known gaps and intentional limits:

- `rnx`, `rnir`, `rnpkg`, `rngit`, and `git-remote-rns` are not implemented. There is on-going work in progress for supporting these.
- `rnodeconf-rs` is partial; safe inspection/configuration and EEPROM
  dump/backup are furthest along. Firmware flashing, autoinstall/update, ROM
  bootstrap, destructive EEPROM wipe, and full signing-key management are not
  implemented.
- `rnstatus-rs` covers the practical operator surface, but does not implement
  every display/API behavior from upstream.
- `rnpath-rs` remote mode is read-only for table/rates, including destination
  filters, apart from the remote blackhole-list query path. Remote mutations
  and remote active path requests are full gaps.
- `rncp-rs` implements the listener `-b` announce interval. `-P/--phy-rates`
  is not supported for the time being.
- `rns-ratkey` hardware identity support is feature-gated and still has known
  hardware-verification gaps before it should be described as release-ready.

## Contributing

If the issue or contribution belongs upstream as well, start there. Python LXMF
and Reticulum remain the reference implementations.

PRs are closed for now until I have time to catch up on everything. I'm tired.

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE).
