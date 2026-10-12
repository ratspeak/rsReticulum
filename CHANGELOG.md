# Changelog

## Unreleased

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
