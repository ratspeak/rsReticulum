# Reticulum application API

`rns_runtime::prelude` is the canonical application-facing import path for an
owned Reticulum runtime. It gathers existing identities from the protocol,
identity, Link, interface, and runtime crates; it does not wrap or replace
them. Module-qualified paths remain supported.

The compiled examples under `crates/rns-runtime/examples/` are the executable
application guide. They cover runtime startup and shutdown, Destinations,
announces, packets and receipts, persistent Links, requests, Channels, Buffer
streams, Resources, and RNode observation.

```rust
use rns_runtime::prelude::*;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let runtime = init().await?;
let identity = Identity::new();

// Application work owns `runtime`; shutdown is explicit and awaitable.
runtime.shutdown().await;
# let _ = identity;
# Ok(())
# }
```

Finite destination discovery uses `resolve_destination_on_transport` with one
deadline and validated identity recall. Long-lived observation uses
`ReticulumHandle::subscribe_announces`, whose returned
`AnnounceSubscription` owns exactly one registration. A finite lookup never
installs or removes an announce handler.

The prelude is intentionally not a blanket stability promise. Low-level actor,
mailbox, RPC, transport-table, concrete-driver, and Link endpoint ownership
paths remain provisional SPI. Advanced integrations may continue using those
module-qualified paths, but application code should start with the prelude and
the compiled examples.

Compatibility is checked in layers:

- `api-baseline/*.txt` records the explicit all-feature Apple ARM64 surface;
- `api-baseline/manifest-contract.json` records features, targets, MSRV, and
  non-development dependencies;
- `api-fixtures` compiles canonical and retained legacy imports as an external
  consumer; and
- `tools/check-api-compatibility.py` rejects removals from the immutable Wave C
  floor.

These checks complement platform builds and protocol/interoperability tests;
they do not replace them.
