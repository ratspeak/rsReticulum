# Reticulum runtime examples

These examples mirror the application-facing subjects in the upstream Python
Reticulum examples while using explicit Rust runtime ownership.

Most networked examples have `server` and `client` modes:

```console
cargo run -p rns-runtime --example link -- server
cargo run -p rns-runtime --example link -- client <destination-hash> "hello"
```

Pass `--config <directory>` to either mode to select a Reticulum config
directory. Servers print their destination hash and announce once at startup.

The `ratchets` example is a local composition recipe because ratchet files and
identity files are application-owned secrets:

```console
cargo run -p rns-runtime --example ratchets -- identity.key ratchets.bin
```

Use private, access-controlled paths for both files in a real application.

Python's `ExampleInterface.py` demonstrates runtime-loaded Python classes.
Rust instead integrates third-party interfaces at compile time through
`rns_interface::InterfaceHandle` and the runtime's interface factory. This is
an intentional ownership and type-safety difference, not a wire-protocol gap.
