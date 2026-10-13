# Capacity, IFAC configuration, and application packet receipts

These changes are part of the unreleased1.4.0 source line. They do not change
the existing published1.3.0 release or establish a new release date.

## Interface ownership and packet capacity

`InterfaceHandle` and `InterfaceEntry` carry an `InterfaceOwner` and an
`InterfacePacketCapacity`. The historical `mtu` field remains available for
statistics. Admission uses the separate clear-packet and IFAC-bearing wire
budgets, and `link_mtu_upgrade` explicitly controls upgrade permission.

Custom drivers must create `InterfaceTransportSender` before starting any task
or callback that can publish input or cleanup events. Copy its `owner()` into
the handle, and retain clones of that sender across carrier reconnects. Each
accepted child and replacement registration needs a fresh sender and owner.
Send inbound packets and driver-originated deregistration through this sender;
raw unowned events are refused. Do not wrap messages twice. Coordinated IFAC or
capacity changes use a new owner revision and rebind producers; ordinary
bitrate/online changes do not establish a new capacity promise.

Async driver sends wait until the actor accepts that owner registration. This
keeps the first packet of a newly accepted connection from racing registration;
retiring the owner releases pending sends with an error. Custom actor harnesses
must explicitly mark the owner registered when they accept its registration.

The conservative custom-driver default is `InterfacePacketCapacity::base(mtu)`.
Explicitly declare additional IFAC headroom or upgrade support only when the
whole-packet driver guarantee supports it. Framing and BLE fragmentation are
outside these budgets. TCP fixed MTUs must fit the actual wire budget after IFAC.
Active IFAC also limits the complete wire packet to HKDF-SHA256's 8160-byte
expansion limit; subtract the configured tag size for its clear-packet ceiling.

General Links require at least 500 clear packet bytes. An interface with less
capacity can still carry fitting non-Link traffic, but reports
`LinkCapacityUnavailable` for general Links. RNode's 508-byte wire budget carries
500 clear bytes with IFAC tags up to eight bytes. Larger tags are never silently
weakened. Current local endpoints remain capped at 500; safe transit can preserve
larger peer offers. Legacy or zero Link signalling means 500; nonzero values below
500, malformed shapes, disabled endpoint modes, and proofs above the original
offer are rejected before endpoint state changes.

Initiators send `SendLinkRequest` with a per-attempt oneshot result, or call
`link_messages::dispatch_link_request`. The result preserves typed capacity
errors before waiting for a proof. Keep one establishment deadline around both
admission and proof waiting. Drop the result receiver when cancelling: an actor
that has not dispatched that attempt then emits no request. This acknowledgement
means local driver admission, not peer receipt. It does not replace signature
verification or the exact interface owner retained from the request/proof path.

## Explicit IFAC units

An explicit `ifac_size` is interpreted as bits only when accompanied by
`ifac_size_unit = bits`. The byte escape hatch is `ifac_size_bytes`; it cannot
coexist with the bits fields. Supported effective sizes are 1–64 bytes. A bare
old `ifac_size` requires migration; its historical meaning is not guessed.
Omitting all size keys retains the interface class default. Explicit malformed
sizes remain errors even when credentials are absent. Disabled interfaces may
retain old settings, but must be migrated before enabling them.

`InterfacePostInit::try_from_section` replaces the infallible constructor. Use
the shared `config::ifac::parse_ifac_size` decoder rather than another parser.
`validate_config_capacity` checks explicit driver promises before spawn.
Malformed file syntax still fails the file; semantic errors isolate the affected
enabled interface.

Preview an explicitly selected migration without starting the network:

```sh
rnsd-rs -c /path/to/config-directory config ifac-units --source-units bytes --interface Radio
```

Use `--source-units bits` when that is the known source convention. Add `--write`
to publish the reviewed plan. Publication checks that the source is unchanged,
takes the shared OS-backed config lock, and retains a unique private backup.
An older binary requires restoring its original configuration before rollback.

## Ordinary Link packet proofs

Ordinary `DATA` with context `None` follows explicit `ProofStrategy` policy.
`ProveNone` delivers without a proof. `ProveAll` preserves automatic proofs and
delivers independently of proof queue admission. `ProveApp` requires both an
exact endpoint dispatch handle and the bounded typed inbound channel; it cannot
use the legacy tuple channel. Configuration setters return a result.

For application-controlled admission, receive `InboundLinkPacket`, retain its
`Bytes` and non-cloneable `LinkPacketReceipt` through validation and persistence,
then consume the receipt with `accept()`. Awaiting its result distinguishes local
driver admission (`Sent`) from expiration, closed ownership, dropping, or failure.
`Sent` does not mean physical radio transmission or remote delivery. Dropping the
receipt produces no proof. `reject_and_close(InvalidPropagationStamp)` orders the
protocol rejection before teardown when it can be admitted. Use
`close_without_proof()` for a storage/quota failure that requires teardown without
claiming an invalid propagation stamp; it retains the same exact-owner checks.

Authority is tied to the exact Link generation. Expired, closed, or replaced
owners cannot send a late proof. Payload clones retain admission credits until
they are actually dropped, even if the receipt expires. Limits are 64 packets
and 2 MiB per Link, and 256 packets and 8 MiB process-wide for this ordinary
application-controlled ingress. Resource, Channel, RPC, Direct, and voice
protocol owners retain their own admission rules.

## Durable storage and local timing

`rns_identity::persistence::durable_write` returns a privately constructed receipt
only after exact verification and the native platform barriers succeed. It is
separate from the existing cache writer. Errors distinguish pre-publication
failure from `CommitUncertain`; keep recovery material and withhold higher-level
acceptance on uncertainty. `durable_reconcile` and bounded streaming
`durable_reconcile_hash` renew barriers as well as verifying bytes. A receipt
attests those calls, not hardware infallibility or the provenance of a message.
Directory migration still requires an application journal and native recovery.

Use `Link::try_extend_establishment_timeout` for checked timeout extension.
Invalid floating-point times and unrepresentable deadlines are rejected before
transport side effects. Channel RTTs have a finite local ceiling and its sending
window remains bounded even when public tuning fields contain extreme values.
