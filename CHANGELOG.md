# Changelog

## Unreleased

- RNode drivers confirm the settings the radio applies once it is on, on every transport, and stop with the rejected setting named (for example TX power below an amplifier's minimum) instead of transmitting at other settings or retrying forever.
- Serial and TCP RNodes keep retrying a port that is missing, busy or not permitted every 5 seconds, as in Python Reticulum, and report which.
- Android Bluetooth RNode sessions wait for the bridge before starting, so a slow reconnect no longer drops a healthy link.
- Interface status reports IFAC like Python Reticulum: `rnstatus-rs` shows the network name and access line only for interfaces that use IFAC.
- Interfaces start only when `enabled` or `interface_enabled` is yes, as in Python Reticulum. A section with neither key is now skipped with a warning instead of starting, so add `enabled = yes` to it. An RNodeMulti subinterface with its own flag follows that flag, so a subinterface set to no never transmits.
- Durable storage works on any filesystem again, as in Python Reticulum, including ZFS, Docker overlays, external drives and network shares. A flush the filesystem lacks is skipped and logged once, and network or RAM-backed storage logs a warning instead of refusing to start.
- A Link accepts the peer's identification as soon as its handshake completes, as in Python Reticulum, so a request a Python client sends right after identifying no longer fails for lack of an identity. Only the receiving side of a Link accepts identification.
- The receiving side of a Link counts its Link proof as sent traffic, as in Python Reticulum, so it no longer answers keepalives before the Link is established and its traffic totals include the proof.
- A connectable I2P interface now starts alongside a Unix-socket shared instance or another connectable I2P interface, and an I2P interface runs one connection for every configured peer, plus its server when connectable, as in Python Reticulum.
- Hub restarts restore saved paths and tunnels as in Python Reticulum.
- Transport hubs now accept tunnel synthesis, so a Python client that reconnects gets its paths back without announcing again, and losing a tunnel's interface no longer drops paths the hub learned through other interfaces, as in Python Reticulum.
- PLAIN and GROUP packets that arrive from more than one hop away, and announces typed PLAIN or GROUP, are dropped before deduplication, as in Python Reticulum.
- TCP, Backbone and I2P client interfaces open every connection with a tunnel synthesis, so a transport hub restores their paths after a reconnect, and traffic queued while a connection was down or failing to open is dropped when it opens, as in Python Reticulum.
- A client of a Unix-socket shared instance drops traffic queued while the instance was unreachable, as in Python Reticulum.
- I2P interfaces announce their own address for discovery, and the peers listed in `peers` keep Python's defaults, sharing only the interface's IFAC, as in Python Reticulum.
- A bootstrap-only I2P interface keeps running once discovered interfaces connect, as in Python Reticulum, which never detaches an I2P interface.
- A connectable I2P interface keeps its I2P address across restarts. Its key is stored in Python Reticulum's key file under `storage/i2p`, readable by its owner only; as in Python Reticulum, a node without `enable_transport` or `static_transport_identity` gets a new address each start.
- Every validated announce refreshes the identity remembered for its destination, including path responses and replays that leave the path unchanged, so a destination's identity stays recallable as in Python Reticulum.
- Python Reticulum 1.5 `rnstatus` and `rnpath` work against `rnsd-rs`, locally and with `-R`: interface stats carry every field they read, including announce and path request counts, violation counters and the transport instance, and remote management answers on the transport identity, as in Python Reticulum.
- `rnstatus-rs -R` and `rnpath-rs -R` take the remote node's transport identity hash, which `rnstatus` shows as the transport instance on a transport node. A node with `enable_transport` off and no `static_transport_identity` gets a new management destination each start, as in Python Reticulum; set `static_transport_identity = yes` on a leaf you manage remotely. `storage/remote_management_identity` is no longer used and can be deleted.
- Announces held during an ingress burst on an IFAC interface are processed when released instead of being dropped, and released or replayed announces no longer count as received traffic again, as in Python Reticulum.
- Interface discovery announces name this stack, `rsRNS`, and its version. `rnsd-rs` auto-connects only to Backbone interfaces announced by Python Reticulum 1.5.2 or later, or to any announced Backbone interface with `autoconnect_unverified_implementations`, and no longer stores or lists discovered TCP client interfaces, as in Python Reticulum.
- Discovery announces a KISS-framed TCP client as a KISS interface and sends and reads unset radio parameters as nil, so Python and `rnsd-rs` read each other's KISS, Weave and RNode announces, as in Python Reticulum.
- `rns_link::clock::ContinuousInstant` reads a monotonic clock that keeps counting while the system is suspended, for deadlines that must hold in real time across a sleep.
- An interface counts a path request in its stats only once its tag passes the duplicate check, as in Python Reticulum 1.5.
- A realtime Link packet dropped at a full transmit queue counts toward the interface's dropped bytes.
- `rnpath -R` filters the remote path and rate tables as Python Reticulum compares them: a destination hash of another length matches nothing, and the hop limit compares as a number instead of wrapping above 255.
- Remote management Links refuse Resources other than requests and responses, as Python Reticulum's do.
- `rnsd-rs` never auto-connects a discovered interface at an onion address, at 127.0.0.1 or 0.0.0.0, or at a host and port that an interface already connects to, as in Python Reticulum.
- Interface stats name the network an auto-connected interface was discovered through (`autoconnect_source`), as in Python Reticulum.
- Decryption, key derivation and identity and ratchet file handling no longer leave copies of keys or plaintext in freed memory, and identity files larger than 1 KiB are refused.
- A 64-byte identity file always loads as a raw key, as in Python Reticulum. About one key in 29,000 began with bytes that were misread as the older envelope format, and its identity failed to load.
- Writing, verifying and recovering state files retries a read that a signal interrupts instead of failing.
- Interface options wipe their IFAC passphrase when dropped, and the debug output of IFAC settings no longer shows it.
- Each interface's IFAC key lives in one allocation that is wiped when dropped, so interface tables no longer leave copies of it in freed memory.
- I2P interfaces no longer leave their private key in freed memory when they read it, store it or exchange it with the SAM bridge. They refuse a key file larger than 16 KiB and, as Python Reticulum's SAM client does, a SAM reply line longer than 64 KiB.
- Remote management answers the profiling flag of `rnstatus -R -z` with empty results, and leaves a status request that is not a list of flags unanswered, as Python Reticulum does.
- `rnstatus-rs` shows the network an auto-connected interface was discovered through on a `Source` line under its name, as Python's `rnstatus` does, and its JSON output carries it as `autoconnect_source`.
- AutoInterface's `devices` and `ignored_devices` take effect, and they and I2P `peers` are read as Python Reticulum reads lists: a quoted name that contains a comma stays one name, and `devices = ,` allows every interface.
- TCP client interfaces read `i2p_tunneled`, as Python Reticulum does, and give a connection tunneled over I2P its longer I2P socket timeouts.
- TCP server and Backbone interfaces are announced for discovery only with `reachable_on` set, and Backbone clients never, as in Python Reticulum. A discoverable server without `reachable_on` logs a warning and is not announced, so set `reachable_on` to keep announcing it. The `discovery_reachable_on` key is no longer read.

## 1.4.0 - 2026-10-12

- Corrected packet-size limits across interfaces and Links, including IFAC overhead, and reject unsupported Link setups before sending them.
- Added application-controlled acknowledgements so propagation nodes can confirm a message only after safely storing it.
- Prevent stale interface or Link callbacks from acknowledging a different connection after reconnect or cancellation.
- Reject malformed Resource metadata and invalid timeout values without panics or excessive allocation.
- Added checked durable file operations for identities, ratchets, and application storage, with explicit recovery after interrupted writes.
- Updated public interface, Link, and storage APIs. This source-breaking release uses the `~1.4.0` compatibility line.

## 1.3.0 - 2026-10-12

### Added

- Added Link bind-readiness polling so applications can start sending as soon as the transport is ready.

### Fixed and improved

- Represent unknown discovery latitude, longitude, and height independently as `None` instead of zero, accept Python nil coordinates, and preserve presence through configuration, storage, and `rnstatus-rs`.
- Register and own the interface-discovery destination, advance publication intervals only after driver admission, and preserve pending announcements across bounded backpressure and reconnect.
- Keep learned mesh announcements out of ordinary RNode control/data backlogs until the final writer can send them, while preserving same-radio relay and announce pacing.
- Retain refused local announcements and attached path answers under bounded ownership tied to the exact interface generation.
- Preserve multiple recursive-discovery requesters, slow-radio deadlines, interface replacement safety, and hidden-peer same-radio responses without letting one cancellation affect another requester.
- Updated btleplug to 0.13.4, including upstream Windows discovery and reconnect fixes. Windows can try an explicitly configured RNode MAC or an eligible remembered BLE Peer absent from scan results, with bounded GATT setup, existing backoff, and signed peer identity checks.
- Installed desktop BLE notification receivers before subscribing and limited packet fragments to the negotiated ATT payload.
- Improved Bluetooth Peer packet sizing and flow control, including Apple write handling and queued sends.
- Fixed a remotely triggerable Link panic when a peer reported an infinite, NaN, negative, or oversized RTT. Peer RTTs follow Python's handling and saturate at the 720-second stale window; initiators ignore LRRTT as Python does.
- Require the corrected Windows socket backend so spawned helper processes cannot keep network listeners alive after the owning runtime shuts down.
- Match Python RNS 1.4.2 Channel receive-window admission by dropping sequence numbers more than 48 slots ahead until a retry falls inside the window.
- Report the bundled `rnsh` compatibility level as 0.3.0 and the `rnsd-rs` interactive compatibility level as RNS 1.4.2.

### Build and compatibility

- Discovery coordinates now use `Option<f64>`, and recursive discovery exposes detached observations and exact requester cancellation instead of public mutable state. Both source-breaking changes are covered by the [1.3 migration guide](api/migrations/1.3.md).
- Project minor versions may include breaking APIs. Select `~1.3.0` or an exact reviewed source revision when adopting this release line.
- Raised the full Rust workspace minimum compiler to Rust 1.89. Apple native BLE bindings declare their required features explicitly; Android consumers must use btleplug's matching 0.13.4 Java bridge and JNI 0.22 initialization.
- Promote exact Python RNS 1.4.2 to the complete release baseline, including live interoperability, source oracles, utility vectors, and corpus provenance. RNS 1.5.0 remains deferred.

## 1.2.0 - 2026-08-17

- Designated the existing `rns_runtime::prelude` and compiled examples as the
  canonical application spine while retaining every module-qualified path,
  and added external-consumer, manifest/feature, and additions-only API
  compatibility gates without changing runtime behavior or public signatures.
- Classified every library package and added pinned, CI-enforced public API
  snapshots so compatibility drift is reviewed before any boundary change;
  no visibility or signature changed in this baseline.
- Made source releases reproducible from an existing immutable component tag:
  packages are non-publishable by default, release builds use the committed
  lockfile and Rust 1.87.0, actions are commit-pinned, and CI verifies the
  manifest, changelog, tag, and checkout contract.
- Isolate exact announce subscriptions from legacy aspect-wide deregistration,
  and resolve finite destination identities through validated recall plus
  deadline-bounded path discovery instead of temporary announce handlers.
- Distinguished the Reticulum 1.3.8 compatibility-floor corpus from the
  current 1.4.2 behavior reference instead of presenting the old oracle as the
  newest upstream target.
- Enforce role-specific Link packet proofs: initiators sign with the transient
  LINKREQUEST key, responders sign with the destination identity, and external
  identity backends no longer fall back to an unrelated key.
- Ignore unauthenticated invalid LRPROOF candidates without closing a pending
  initiator, allowing the authentic proof to win an interface race.
- Bind every locally owned established Link endpoint to its validated
  interface and role, with fail-closed routing, bounded ordered control egress,
  terminal interface-loss notification, and bounded best-effort realtime
  egress. Typed send rejection closes only the exact owner, while final
  LINKCLOSE and temporary-destination cleanup drain atomically in order.
  Initial LINKREQUEST discovery remains path-routed or broadcast.
- Forward authenticated non-Link packet delivery proofs from `LinkManager` to
  owning applications through a lossless completion channel.
- Retain and retry destination announcements, including path responses, when
  the bounded transport ingress is temporarily saturated.
- Let one-shot Link clients reuse a validated cached identity when its route is
  still live, matching Python recall behavior and avoiding redundant path
  discovery.
- Keep completed `rncp` Links alive for Python's receiver-side Resource
  conclusion callback before sending the authenticated teardown.
- This source line includes application and runtime API evolution since 1.1.0;
  downstream integrations should qualify against the 1.2 dependency line.

## 1.1.0 - 2026-07-26

- Added application-facing Destination, announce, receipt, Link, request,
  Channel, Buffer, and Resource APIs.
- Added resilient long-running Link sessions with recovery, liveness,
  cancellation, progress, metrics, and responder lifecycle support.
- Hardened delivery proofs, shared-instance authority and reconnection, IFAC
  ingress, persistence, routing snapshots, and orderly shutdown.
- Expanded RNode lifecycle, capability, BLE, USB, TCP, serial, and safe
  `rnodeconf-rs` support.
- Added compiled examples and stricter MSRV, Clippy, interoperability, and
  public-documentation gates.
