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

## Explicit shared-instance ownership

Applications that require authenticated shared control can opt into
`reticulum::init_with_policy` and `shared_instance::InstancePolicy`:

- `Configured` retains the normal config-driven automatic owner/client behavior.
- `Standalone` owns local interfaces without exposing shared IPC.
- `SharedOwner` binds both configured shared endpoints or fails; it never joins
  another owner. `SharedOwnerAt(endpoint)` selects them in memory without
  rewriting the configuration file.
- `SharedClient(credentials)` requires the selected packet endpoint and
  authenticated interface-status RPC before becoming ready. It reauthenticates
  on reconnect and never falls back to local interfaces.

`SharedInstanceEndpoint::Tcp` is loopback-only. Explicit Unix endpoints use
Linux/Android abstract instance names. Keys are opaque HMAC bytes, supplied via
`SharedInstanceCredentials::new`; its debug representation redacts the key.
`credentials.test().await` checks availability without starting a runtime.

Observe reconnect/authentication state through `shared_instance_state()` and
typed control failures through `query_control_result()`. Client runtimes reject
dynamic local interface spawns. Non-fatal configured-interface startup failures
are available through `startup_interface_failures()`; other interfaces can
remain usable.

Upstream packet IPC is unauthenticated: successful RPC authenticates the control
endpoint, not the identity of the packet socket. Selecting a trustworthy matching
pair remains the application's responsibility. These policies do not move
AutoInterface's interoperable UDP ports or alter Reticulum wire formats.

## Stability

Applications that own retry policy can obtain
`ReticulumHandle::path_recovery_handle()` (also available from the application
prelude). `try_recover(destination, Some(failed_link_id))` requests an atomic
comparison with the route actually used by that locally originated Link. Only
the unchanged route can be invalidated; fresh routes on the same interface are
not suppressed. `None` requests bounded discovery without route invalidation.
The 64-operation admission queue reports backpressure; callers retain ownership
and bound their reply wait. Discovery is coalesced per destination, and the
result is not proof of radio transmission or delivery. Old or unobserved Link
attempts cannot delete routes. Shared clients only affect their own local
transport state and use normal packet IPC for discovery.

`try_recover_packet(destination, packet_hash)` provides the same comparison for
an atomically tracked local `SendPacket` attempt. Packet and Link ownership are
separate; failures cannot consume another kind of attempt. Packet receipt
windows can use `rns_wire::receipt::receipt_timeout_for_route`, also used by the
runtime's automatic packet receipt policy.

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
