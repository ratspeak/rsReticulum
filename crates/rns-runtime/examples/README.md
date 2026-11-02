# Reticulum runtime examples

These examples use the 1.4 source API and `rns_runtime::prelude`. Run them from
the rsReticulum repository root after installing the [build prerequisites](../../../README.md#build-it).
They demonstrate application ownership; they are not ready-made services.

## Run a client and server

Most examples have `server` and `client` modes. Start the server in one terminal:

```sh
cargo run -p rns-runtime --example link -- server --config /path/to/server-config
```

Copy the printed 32-character destination hash, then run the client from another
terminal or host connected to the same Reticulum network:

```sh
cargo run -p rns-runtime --example link -- client "DESTINATION_HASH" "hello" --config /path/to/client-config
```

Replace the paths and hash. `--config` selects a directory containing a Reticulum
`config` file. Without it, the example uses the normal rsReticulum configuration
and may attach to its shared instance. Two standalone owners on one host need
different shared-instance ports or sharing disabled. An empty or disconnected
configuration does not provide a path between the examples.

Each server creates a temporary identity on startup, prints its destination and
announces once; its address changes after a restart. `announce` is different:
it announces when you press Enter. Networked examples use the configured
interfaces, so run demonstrations on a network you control. Stop servers with
Ctrl-C.

## Choose an example

All commands start with `cargo run -p rns-runtime --example NAME --`. Arguments
below follow the `--`; networked examples also accept `--config DIRECTORY`.

| Example | Arguments and result |
| --- | --- |
| `minimal` | No positional arguments. Announces and prints received packets with automatic proofs enabled. |
| `announce` | No positional arguments. Observes matching announces; Enter sends an announce with `Peach` app data. |
| `broadcast` | Optional message. Sends a PLAIN broadcast without encryption or a delivery receipt. |
| `echo` | `server`, or `client HASH [MESSAGE]`. The client waits for a packet proof, not an echoed message. |
| `link` | `server`, or `client HASH [MESSAGE]`. Exchanges a message and reply over a Link. |
| `identify` | `server`, or `client HASH`. Demonstrates initiator identification on a Link. |
| `request` | `server`, or `client HASH [MESSAGE]`. Requests `/echo`; the example handler allows all callers. |
| `channel` | `server`, or `client HASH [MESSAGE]`. Exchanges a custom Channel message. |
| `buffer` | `server`, or `client HASH [MESSAGE]`. Exchanges a short UTF-8 string using Buffer/stream frames. Use the default short message; this example adds a reply prefix per received frame and is not an arbitrary-length echo protocol. |
| `resource` | `server`, or `client HASH [MESSAGE]`. Transfers a Resource with progress reporting. |
| `filetransfer` | `server NEW_OUTPUT_FILE`, or `client HASH INPUT_FILE`. Writes the first completed Resource to a new file and refuses to replace an existing file. |
| `speedtest` | `server`, or `client HASH [BYTE_COUNT]`. Queues Link packets; the default is 2 MiB. |
| `ratchets` | `IDENTITY_FILE RATCHET_FILE [MESSAGE]`. Local key persistence and encrypt/decrypt composition; it does not start a network runtime. |

Resource and file-transfer servers accept incoming Resources without a caller
allow-list. The file-transfer destination is a demonstration endpoint, not an
authenticated file-sharing service. A Resource completion is a transport result;
it does not acknowledge the receiving application's later file write.

The speed-test client's rate measures local queue submission, not delivered
network throughput. Its server prints a rate measured from server startup,
including idle time; after its counter resets, that rate is not a per-batch
benchmark. Use a dedicated benchmark with receiver-confirmed bytes for network
capacity measurements.

## Local ratchet example

The ratchet example creates missing identity and ratchet files and reuses
existing ones:

```sh
cargo run -p rns-runtime --example ratchets -- identity.key ratchets.bin
```

Use new test paths for a demonstration and private, access-controlled paths in
a real application. Ratchet files and identity files are application-owned
secrets. The example retains its ratchet key; demonstrating encryption with
that key alone does not demonstrate key retirement or forward secrecy.

Python's `ExampleInterface.py` loads Python classes at runtime. Rust integrates
third-party interfaces at compile time through `rns_interface::InterfaceHandle`
and the interface factory. Custom drivers on the 1.4 line must also follow the
[interface ownership and capacity contract](../../../api/migrations/capacity-and-receipts.md).
