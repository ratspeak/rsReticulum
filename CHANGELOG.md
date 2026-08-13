# Changelog

## Unreleased

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
