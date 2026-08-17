# Rust API

Application code should begin with `rns_runtime::prelude`. It collects the
runtime handle and the commonly used identity, destination, packet, Link,
request, Channel, Resource, interface, and shutdown types without wrapping or
replacing them. Existing module-qualified imports remain supported.

The examples in `crates/rns-runtime/examples/` are compiled as part of CI and
show complete flows for runtime startup, Destinations, announces, receipts,
Links, requests, Channels, Buffer streams, Resources, and RNode observation.

```rust
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use rns_runtime::prelude::*;

#[tokio::main]
async fn main() -> Result<(), ReticulumError> {
    let runtime = init(
        None,
        None,
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(true)),
    )
    .await?;

    let identity = Identity::new();
    // Use `runtime` and `identity` to create application Destinations.

    runtime.shutdown_and_wait().await;
    Ok(())
}
```

Finite destination discovery uses `resolve_destination_on_transport` with one
deadline and validated identity recall. Long-lived announce observation uses
`ReticulumHandle::subscribe_announces`; the returned `AnnounceSubscription`
owns exactly one registration. Finite lookups do not install or remove
announce handlers.

## Stability

The application prelude is the recommended integration path, but the workspace
is not yet a blanket stability promise for every public Rust item.

- `rns-identity`, `rns-link`, `rns-protocol`, and `rns-interface` are candidate
  stable.
- `rns-crypto`, `rns-wire`, and `rns-transport` are provisional low-level
  packages.
- `rns-runtime` is provisional because it contains both the application
  prelude and lower-level actor, RPC, manager, and command APIs.
- `rns-ratkey` is experimental, and the `rns-tools` library target supports the
  repository's binaries rather than a public library integration.

Low-level actor, mailbox, RPC, transport-table, concrete-driver, and Link
endpoint ownership APIs remain available for compatibility. They should not be
treated as stable merely because they are publicly reachable.

## Compatibility checks

The `api/` directory contains the evidence used by CI:

- `stability.json` records package tiers, source commits, snapshot hashes, and
  the current review decision;
- `snapshots/` records the explicit all-feature Apple ARM64 Rust API and the
  manifest, feature, dependency, target, and MSRV contract; and
- `fixtures/` compiles recommended and retained import paths as an external
  consumer.

These checks catch accidental changes, but they do not replace platform builds,
protocol interoperability tests, or manual review. In particular, the API
snapshot omits auto-derived, auto-trait, and blanket implementations and is not
by itself a complete SemVer verdict.

Run the checks with:

```sh
python3 tools/check-api-baseline.py
python3 tools/check-api-manifest.py
python3 tools/check-api-compatibility.py
cargo check --manifest-path api/fixtures/Cargo.toml --locked
cargo check --manifest-path api/fixtures/Cargo.toml --all-features --locked
```

Snapshot updates require a clean source commit and an explicit review recorded
in `api/stability.json`. Additions, removals, deprecations, platform impact, and
version consequences must be reviewed before accepting new evidence.
