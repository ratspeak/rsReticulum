<div align="center">

# rsReticulum

**A Rust implementation of Reticulum.**


[![License: Reticulum License](https://img.shields.io/badge/license-Reticulum%20License-blue.svg)](LICENSE)
[![Rust 1.89+](https://img.shields.io/badge/rust-1.89%2B-orange.svg)](https://www.rust-lang.org)
[![Baseline: Reticulum 1.6.0](https://img.shields.io/badge/baseline-Reticulum%201.6.0-success.svg)](https://reticulum.network/)
[![Status](https://img.shields.io/badge/status-experimental-yellow.svg)](#compatibility-notes)

[Reticulum Manual](https://reticulum.network/manual/) |
[Ratspeak](https://github.com/ratspeak/Ratspeak) |
[rsLXMF](https://github.com/ratspeak/rsLXMF) |
[Reticulum](https://github.com/markqvist/Reticulum)

</div>

---

rsReticulum is a Rust port of
[Reticulum](https://github.com/markqvist/Reticulum), the reference
implementation by Mark Qvist. It was written from the reference source, not from
a specification, and tracks the reference's wire behavior release by release.

## Contents

- [Build It](#build-it)
- [Rust API](api/README.md)
- [Tool Usage](#tool-usage)
- [Configuration](#configuration)
- [Interface Support](#interface-support)
- [Compatibility Notes](#compatibility-notes)
- [License](#license)

## Build It

This guide describes the 1.5.1 release, [v1.5.1](https://github.com/ratspeak/rsReticulum/releases/tag/v1.5.1), the source line Ratspeak builds from.

From a new working directory:

```bash
git clone https://github.com/ratspeak/rsReticulum.git
git -C rsReticulum checkout --detach v1.5.1
cd rsReticulum
```

Run the build commands below from that directory. The host crates require Rust 1.89 or newer. The default build compiles a bundled SQLite, so it also needs a C compiler; the build tools below provide one.

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

The `rns-tools` and `rns-git` crates build these tools:

| Binary | Purpose |
| --- | --- |
| rnsd-rs | Shared Reticulum daemon. Owns interfaces and local control sockets. |
| rnstatus-rs | Interface, announce, path, link, and aggregate status. |
| rnpath-rs | Path lookup, path table inspection, rates, drops, and blackhole actions. |
| rnid-rs | Identity generation, inspection, public/private import/export, hashing, signing, verification, encryption, and decryption. |
| rnprobe-rs | Destination probe utility with loss and round-trip reporting. |
| rncp-rs | File transfer utility with send, listen, and authenticated fetch modes. |
| rnodeconf-rs | RNode inspection, settings, signing, EEPROM bootstrap, firmware install and update, and the guided installer. |
| rnsh-rs | Reticulum shell listener/client. |
| rnx-rs | Remote command execution listener and client. |
| rnir-rs | Distributed identity resolver. Like upstream's `rnir`, it starts Reticulum and exits. |
| rnpkg-rs | Meta package manager. Like upstream's `rnpkg`, it starts Reticulum and exits. |
| rngit-rs | Git repository node and its management commands, with forks, mirrors, releases, and NomadNet pages. |
| git-remote-rns | Git remote helper for `rns://<destination_hash>/<group>/<repo>` URLs. Python's `rngit` installs one with the same name, so keep only one on `PATH`. |
| rngcs-rs | Git commit signer and verifier for Reticulum identities, with the `ssh-keygen -Y` interface git uses for SSH signing. |

Common command forms (use each binary’s `--help` for the complete option list):

```text
rnsd-rs     [--config CONFIG_DIR] [-v|-q]... [-i] [--service] [--exampleconfig] [--version]
rnsd-rs     [--config CONFIG_DIR] config ifac-units --interface NAME --source-units bytes|bits [--write]
rnstatus-rs [--all] [--sort rate|traffic|rx|tx|rxs|txs|announces|arx|atx|arxc|atxc|prx|ptx|prxc|ptxc|held|pvs|ivs|flt|txdrp|txdrb|txbuf]
         [--reverse] [--announce-stats] [--link-stats] [--totals] [--json]
         [-d|--discovered] [-D] [-m [-I SECONDS]] [FILTER]
         [-R <transport_hash> -i <identity_file>]
rnstatus-rs --attach NAME | --detach NAME | --reload NAME
rnpath-rs   [--table|--rates] [destination_hash] [--max HOPS]
rnpath-rs   <destination_hash>
rnprobe-rs  [-s SIZE] [-n COUNT] [-t TIMEOUT] [-w WAIT] [--json] <full_name> <destination_hash>
rnid-rs     [-i IDENTITY|-g FILE|-m PUB|-M PRV] [-p|-P] [-x|-X] [-H ASPECT]
            [-a [ASPECT]] [-e FILE|-d FILE|-s FILE|-V FILE] [-w FILE] [-f]
            [-R|-N] [-t SECONDS] [-b|-B] [--raw] [--version]
rncp-rs     <file> <destination_hash>
rncp-rs     -l [-b SECONDS] [-s DEST_DIR] [-a <allowed_hash>]...
rncp-rs     -l -F [-j <jail_dir>] [-a <allowed_hash>|-n]...
rncp-rs     -f <remote_path> <destination_hash> [-s DEST_DIR]
rnodeconf-rs [-i] [--config] [--eeprom-backup|--eeprom-dump] [--version] [PORT]
rnodeconf-rs -T --freq HZ --bw HZ --txp DBM --sf SF --cr CR PORT
rnodeconf-rs -N PORT
rnodeconf-rs -a [PORT]
rnodeconf-rs -u [-U] [--fw-version V] [--fw-url URL] [--nocheck] PORT
rnsh-rs     -l [-i FILE] [-s NAME] [-b PERIOD] [-a HASH]... [-n] [-A|-C] [-- CMD...]
rnsh-rs     [-i FILE] [-s NAME] [-N] [-m] [-w SECONDS] <destination_hash> [-- CMD...]
rnx-rs      -l [-i FILE] [-b] [-a <allowed_hash>]... [-n]
rnx-rs      [-i FILE] [-N] [-d] [-m] [-w SECONDS] [-W SECONDS] <destination_hash> <command>
rnx-rs      -x [-i FILE] <destination_hash>
rngit-rs    [--config DIR] [--rnsconfig DIR] [-p] [-s]
rngit-rs    create|fork|mirror|sync|release|perms|work [OPTIONS] ...
git clone   rns://<destination_hash>/<group>/<repo>
```

Add `target/release`, or the `bin/` directory of a release archive, to `PATH`
to run the tools by name.

### File transfer

An `rncp-rs` listener accepts files only from identities given with `-a` or
listed in `allowed_identities`; `-n` accepts anyone. Add `-F` to also serve
fetches, and `-j <dir>` to keep them inside one directory.

### RNode setup

`rnodeconf-rs` installs and updates RNode firmware, changes device settings,
signs devices, and walks through a new device with `-a`. Flashing uses the same
tools as Python's `rnodeconf`: `avrdude`, `adafruit-nrfutil`, or the firmware's
own `esptool.py` through `python3`.

### Identities

`rnid-rs` creates, imports, and exports identities, and signs, verifies,
encrypts, and decrypts with them. Exported private keys grant control of an
identity, so keep them out of shared terminals, logs, and shell history.
Hardware-backed identities (`rnid-rs hw`, behind the `hardware` feature) are
experimental.

```bash
mkdir -p ~/.rsReticulum/identities
rnid-rs -g ~/.rsReticulum/identities/mgmt              # generate
rnid-rs -i ~/.rsReticulum/identities/mgmt -p           # show
rnid-rs -i ~/.rsReticulum/identities/mgmt -w mgmt.pub  # write the public half
rnid-rs -i ~/.rsReticulum/identities/mgmt -s message.txt   # sign: message.txt.rsg
rnid-rs -V message.txt.rsg                             # verify
rnid-rs -i mgmt.pub -e message.txt                     # encrypt: message.txt.rfe
rnid-rs -i ~/.rsReticulum/identities/mgmt -d message.txt.rfe   # decrypt
```

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
enable_transport = no

[interfaces]

  [[Default TCP]]
    type = TCPClientInterface
    enabled = yes
    target_host = reticulum.example.org
    target_port = 4242
```

Each interface needs a supported type and an explicit `enabled = yes` or `interface_enabled = yes`, and `ifac_size` is given in bits, as in Python Reticulum. Keep unsupported interfaces disabled.

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

Runtime state is kept under `<config-dir>/storage/`. Known destinations and
received ratchets are stored in `known_destinations.db` and cached announces in
`cache/announces.db`, SQLite files in the format Python Reticulum 1.6.0 uses.
A shared-instance client reads the owner's database and never
writes it. A database that cannot be opened is replaced by in-memory state for
that session, with one log line. These stores come from the default
`sqlite-store` feature of `rns-transport`; without it, this state lasts only
for the session.

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
| Backbone | Config-backed `BackboneInterface` listener and `BackboneClientInterface`, HDLC over TCP. |
| Serial, KISS, RNode, RNode Multi, AX.25 KISS | Config-backed with the `serial` feature. |
| RNode over TCP | Config-backed `RNodeInterface` with a `tcp://` port, with the `serial` or `rnode-tcp` feature. |
| BLE RNode | Config-backed with the `ble` feature. |
| Bluetooth Peer | Runtime API used by Ratspeak, with the `ble` feature. |
| Android USB-OTG | Runtime API for Android app embeddings. |
| Weave | Not supported yet. |
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

rsReticulum 1.5.1 follows Python Reticulum 1.6.0, and its tools name that
release in `--version`.

Interface discovery announces this stack as `rsRNS`. `rnsd-rs` auto-connects to
discovered Backbone interfaces announced by Python Reticulum 1.5.7 or later and
by rsReticulum 1.5.0 or later; `autoconnect_unverified_implementations = yes`
in `[reticulum]` allows any. Python Reticulum auto-connects to an rsReticulum
interface only with that option set.

## License

rsReticulum is licensed under the [Reticulum License](LICENSE), the license of
the reference implementation it is ported from. Copyright (c) 2016-2026 Mark
Qvist, unless otherwise noted; additions and modifications Copyright (c) 2026
Ratspeak LLC.

The license is permissive with two conditions: no use in systems built to
purposefully harm people, and no use in or contribution to AI or language-model
training. The copyright and permission notice must stay in every copy.
[LICENSE](LICENSE) is the binding text.
