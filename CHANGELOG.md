# Changelog

## Unreleased

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
