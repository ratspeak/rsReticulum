# Migrating to the next rsReticulum release (draft)

This draft covers source and behaviour changes since the published 1.4.0
release (commit `14241a3`). The crates now follow Reticulum 1.6.0. The release
number belongs to the owner and is not chosen here.

Project minor releases can break the Rust API. Pin an explicit compatible line
or a reviewed Git revision. Upstream line references below are to Reticulum
1.6.0 (`RNS/...:line`).

`api/stability.json` lists every removed snapshot line under
`approvedBreakingChanges`, and this guide explains each one. Most additions are
new public fields and variants. Exhaustive struct literals and exhaustive
`match`es over the types listed in "New fields and variants" no longer compile
until you add the new members, `..Default::default()` or `..T::new(..)`, or a
wildcard arm.

## Stamps: fractional costs and values everywhere

Reticulum 1.6.0 measures stamp work as a fractional value (`RNS/Stamps.py:104-190`,
`stamp_value` returns a float) and reads costs as floats. Every stamp cost,
stamp value and required value in the public API is now `f64`.

| Old | New |
| --- | --- |
| `DiscoveryStamper::generate(&self, &[u8; 32], u8)` | `generate(&self, &[u8; 32], f64, &StampControl)` |
| `DiscoveryStamper::valid(.., u8)` / `value(..) -> u8` | `valid(.., f64)` / `value(..) -> f64` (also `NullStamper`, `RnsDiscoveryStamper`) |
| `discovery::DEFAULT_STAMP_VALUE: u8` | `f64` (`RNS/Discovery.py:77`) |
| `discovery::WORKBLOCK_EXPAND_ROUNDS: u32` | `usize` |
| `AnnounceRequest`, `DiscoveryInterfaceConfig`, `DiscoveredInterface::stamp_value: u8` | `f64` |
| `ReceiverConfig::required_value: u8` | `f64` (`RNS/Discovery.py:262-264`) |
| `ReticulumConfig::discover_interfaces_required_value: u8` | `f64` |

`rns_identity::stamps::StampControl { cancel, deadline, threads }` replaces the
bare cancellation flag. `StampControl::default()` gives an uncancelled,
unbounded, single-threaded search. Use one clone per search and set `cancel`
to stop it.

```rust
let control = rns_identity::stamps::StampControl::default();
let stamp = stamper.generate(&infohash, 16.0, &control);
```

`rns_identity::stamps` (`stamp_workblock`, `stamp_value`, `stamp_valid`,
`generate_stamp`, `generate_stamped_key`) is the shared primitive the transport,
link and LXMF stampers use. The `[stamps]` config section
(`RNS/Reticulum.py:505-512`) and `InitOptions::{enable_stamping, enforce_stamps}`
control it.

## Starting the runtime

- `InitOptions` gains `enable_stamping`, `enforce_stamps` and
  `keep_starting_after_interface_failure`. It derives `Default`; build it with
  `..Default::default()`.
- `ReticulumConfig` gains `filter`, `stamps`, `inbound_queue_lengths`,
  `enable_interface_management`, `default_gravity`,
  `autoconnect_interface_gravity` and the autoconnect keys. It implements
  `Default`.
- `rns_tools::init_tracing` takes `rns_tools::LogLevel` instead of
  `tracing::Level`. This follows Python's nine numeric levels
  (`RNS/__init__.py:60-68`), including Notice (3) and Pathing (7), which
  `tracing` cannot express:

  ```rust
  // old
  rns_tools::init_tracing(tracing::Level::INFO, true, false, std::io::stderr);
  // new
  rns_tools::init_tracing(rns_tools::LogLevel::clamped(3), true, false, std::io::stderr);
  ```

  `LogLevel::filter()` gives the tracing filter. `Utility::loglevel` gives each
  tool's upstream level rule.
- `rns_runtime::jobs::JobScheduler::request_persist` is removed. Persistence
  now runs on upstream's save cadence.
- `rns_runtime::constants::MAX_QUEUED_ANNOUNCES` is now a re-export of
  `rns_transport::constants::MAX_QUEUED_ANNOUNCES`. The import path still works;
  the snapshot records it as a `pub use`.

## Interfaces

| Old | New | Reason |
| --- | --- | --- |
| `TcpServerConfig::listen_ip: String`, `BackboneServerConfig::listen_ip: String` | `Option<String>`; `None` binds the device or wildcard address | `bindip = c["listen_ip"] if "listen_ip" in c else None` (`RNS/Interfaces/TCPInterface.py:518`) |
| `RNodeConfig`, `BleRNodeConfig`, `SubInterfaceConfig`, and the runtime `*InterfaceConfig`/`*RuntimeArgs` `st_alock`/`lt_alock: Option<f32>` | `Option<f64>` | `float(c["airtime_limit_short"])` (`RNS/Interfaces/RNodeInterface.py:159`) |
| `RNodeConfigValidationError::NonFinite { value: f32 }` | `value: f64` | same |
| `SubInterfaceConfig::tx_power: u8` (and `RNodeSubInterfaceConfig`) | `i8` | `int(subinterface_config["txpower"])` (`RNS/Interfaces/RNodeMultiInterface.py:199`) |
| `RNodeMultiConfig::flow_control` | `SubInterfaceConfig::flow_control` (per radio) | `RNS/Interfaces/RNodeMultiInterface.py:205-206` |
| `SubInterfaceConfig::mode` | `RNodeMultiConfig::mode` (one mode for the device); sub-interfaces gain `outgoing` | `RNS/Interfaces/RNodeMultiInterface.py:212` |
| `RNodeResponse::Ready(bool)` | `RNodeResponse::Ready` | |
| `process_rnode_response(cmd, data, id, &mut Option<f32>, &mut Option<f32>)` | `process_rnode_response(cmd, data, id, &mut RNodeSignalStats, Option<u8>)` | RSSI, SNR and Q are kept together, as the `r_stat_*` attributes are |
| `spawn_auto_interface(cfg, id, transport_tx, running)` | `spawn_auto_interface(cfg, id, next_id: Arc<AtomicU64>, transport_tx, spawned_tx, running)` | AutoInterface spawns one child interface per peer (`RNS/Interfaces/AutoInterface.py:134`, `:392`) |
| `McastAddrType: FromStr<Err = String>` | `Err = Infallible` | upstream accepts any value |
| `DiscoveryInterfaceConfig::backbone(String, ..)`, `DiscoveryInterfaceConfig::name: String` | `Option<String>`; `None` sends nil | `interface.discovery_name` may be unset (`RNS/Discovery.py:173`) |
| `DiscoveryInterfaceConfig::modulation`, `DiscoveryInfo::modulation: Option<String>` | `Option<DiscoveryModulation>` | |

These constants are removed. The reconnect waits are now fixed per driver, as
upstream's are:

- `tcp::RECONNECT_WAIT_INITIAL`, `tcp::RECONNECT_WAIT_MAX`
- `i2p::RECONNECT_WAIT_MAX`
- `backbone::CHILD_BITRATE_GUESS`
- `traits::IC_BURST_MIN_SAMPLES`
- `rns_transport::constants::IC_BURST_MIN_SAMPLES`

TCP, Backbone and server configs gain `bitrate` and `ifac_size`, which feed the
hardware MTU (`RNS/Interfaces/Interface.py:255-267`). Build them with `new`.

## Transport tables and statistics

| Old | New | Reason |
| --- | --- | --- |
| `IngressController::{incoming,outgoing}_{announce,pr}_frequency(&self)` | `&mut self`; `outgoing_pr_frequency(&mut self, preemptive: bool)` | the frequency readers drop stale samples (`RNS/Interfaces/Interface.py:366-408`) |
| `RateTable::record`, `RateTable::get_rate`, `RateEntry::rate` field | `check_interface_rate`, `last_announce`, `RateEntry::rate()` method | `AnnounceRateTable` (`RNS/Storage.py:38`) |
| `RateTable::cull(&mut self, f64)` | `cull(&mut self, now, ttl) -> usize` | `RNS/Storage.py:108` |
| `rate_limit::RATE_PENALTY_BASE`, `RATE_PENALTY_MAX`, `RATE_VIOLATIONS_BEFORE_PENALTY`, `RATE_VIOLATION_THRESHOLD` | removed | upstream has no such penalties |
| `PathEntry::touch()` | `PathEntry::used: f64`; transport sets it on use | `path_entry[IDX_PT_USED] = outbound_time` (`RNS/Transport.py:1618`) |
| `ifac::MAX_IFAC_WIRE_BYTES`, `IfacSignError::PacketTooLarge` | removed | |
| `TransportActor::packet_metrics`, `packet_metrics_order` | `packet_rssi_cache`, `packet_snr_cache`, `packet_q_cache` | |
| `discovery::storage::classify(u64)`, `DiscoveredInterface::{discovered,last_heard}: u64` | `f64` timestamps | `time.time()` (`RNS/Discovery.py:604`) |
| `discovery::build_local_manifest` | `build_manifest` | |

`TransportMessage` and `TransportQuery` gain the variants listed below. Code that
matches on them needs a wildcard arm.

`ReceiptUpdate::Delivered { rtt }` gains `proof_hash: Option<[u8; 32]>` and
`metrics: PacketMetrics`, the proof packet's hash and reception statistics;
match it with `Delivered { rtt, .. }`. `rns_runtime::probe::ProbeOutcome` gains
the same two fields, which `rnprobe` prints as upstream reads them from the
receipt's proof packet (`RNS/Utilities/rnprobe.py:166`).

## Links, requests and channels

**Request replies.** Request handlers now produce upstream's reply forms
(`RNS/Link.py:922-935`):

```rust
// old
RequestOutcome::Reply(packed_value)
RequestOutcome::ReplyWithResource { ack, data, metadata, auto_compress }
// new
RequestOutcome::ReplyValue(packed_value)     // one complete MessagePack value
RequestOutcome::ReplyBytes(raw)              // Python receives `bytes`
RequestOutcome::ReplyFile { source: Box::new(file), metadata: None } // [file, metadata]
RequestOutcome::ReplyWithResource { ack, source: Box::new(std::io::Cursor::new(data)), metadata, auto_compress }
```

`source` is any `Read + Seek + Send` (`ResourceSource`).

**Compression policy.** `register_request_handler`,
`register_deferred_request_handler`,
`DestinationHandle::register_request_handler` and
`LinkManagerCommand::RegisterRequestHandler::auto_compress` take
`impl Into<AutoCompress>` instead of `bool`. Existing `true`/`false` arguments
still compile. `AutoCompress::Limit(bytes)` is Python's integer form
(`RNS/Resource.py:372-381`).

**Deferred handlers on a destination.**
`DestinationHandle::register_deferred_request_handler` registers a handler
that answers later through its `DeferredRequestResponder`, so long work stays
off the link-manager task. `register_deferred_request_handler_with` (also on
`LinkManager`) takes a `DeferredAdmission` in place of the reply byte limit:

```rust
let admission = DeferredAdmission::new(64 * 1024)   // largest in-memory reply
    .request_copies(3)                              // copies of the request held
    .busy_reply(b"busy".to_vec())                   // sent when the job limit is reached
    .too_large_reply(b"too large".to_vec());        // sent when the job cannot fit
```

Without the two replies a refused job is dropped, as before. Jobs are admitted
against a process-wide budget; upstream serves every request synchronously
and has none (`RNS/Link.py:891-940`). `DeferredAdmission` is in the prelude.
`LinkManagerCommand` gains `RegisterDeferredRequestHandler`, and
`DestinationRuntimeOptions` gains `endpoint_dispatch`; build the options with
`..Default::default()`.

**Close reasons.** `rns_link::link::CloseReason` is `#[non_exhaustive]` and
gains `StampFailure` (`RNS/Link.py:116-119`). Add a wildcard arm.

**Link stamps.** `Link::new_stamped_initiator`, `rns_link::stamp`, and
`LinkClientError`/`LinkSessionError::Stamp(LinkStampError)` are new. Code that
matches these errors exhaustively needs the new arms.

**Buffers.** The channel buffer types are renamed and follow `RNS/Buffer.py:298-349`:

| Old | New |
| --- | --- |
| `LinkSessionBuffer` | `BidirectionalBuffer` |
| `LinkSessionBufferReader` / `LinkSessionBufferWriter` | `BufferReader` / `BufferWriter` |
| `LinkSessionBufferError` | `BufferError` (gains `Link`, `Session`, `ManagerUnavailable`) |
| `LinkSessionBuffer::reader()/writer()` | `into_split()` |
| `LinkSessionBufferWriter::with_close_timeout`, `DEFAULT_CLOSE_TIMEOUT`, `DEFAULT_READER_CAPACITY` | removed; the writer's close follows the channel window |

`LinkSessionChannelHandle::create_reader`, `create_reader_with_capacity`,
`create_writer` and `create_bidirectional_buffer` return the new types.
`DestinationHandle` gains the same constructors.

## Resources

- `MultiSegmentOutbound::with_options` takes a trailing `Option<usize>`, the
  link SDU to slice parts by. `None` keeps the base MTU. Parts follow the
  link's MTU (`RNS/Link.py:392-397`).
- `WindowState::grow(&mut self, usize)` is now `grow(&mut self)`; the window
  grows by one per completed round (`RNS/Resource.py:917`).
- `ResourceError::DecompressedTooLarge`, `TransferAction` and
  `ResourceFlags::app_flag` are new. `InboundTransfer`, `OutboundTransfer` and
  `MultiSegmentInbound` gain public fields.

## Crypto

- `X25519PrivateKey::exchange` returns `Result<[u8; 32], X25519Error>` and
  rejects a low-order peer key (all-zero secret). This matches Python's default
  backend, which delegates to `cryptography` (`RNS/Cryptography/__init__.py:46-48`,
  `RNS/Cryptography/Proxies.py:60-61`):

  ```rust
  let shared = private.exchange(&peer)?; // X25519Error::LowOrderPoint
  ```

- `HkdfError::OutputTooLong(usize)` is removed. The only length error is
  `InvalidLength` for zero, as `hkdf` raises only for `length < 1`
  (`RNS/Cryptography/HKDF.py:47`).
- `IdentityError::EncryptionFailed` and `DestinationError::InvalidLinkCost` are
  new variants.

## Tools (rncp, rnsh)

- `RncpSendRequest::data: Vec<u8>` becomes `source: Box<dyn ResourceSource>`.
  The file is streamed, as `RNS.Resource(open(file_path, "rb"), ..)` does
  (`RNS/Utilities/rncp.py:721`).
- `RncpSendRequest`/`RncpFetchRequest`: `overall_timeout` and `path_wait` are
  replaced by `path_timeout` (`timeout`, `RNS/Utilities/rncp.py:405`, `:662`)
  and `shutdown: Option<ShutdownSignal>`.
- `progress_tx` carries `RncpProgress { progress, phy_bytes }` instead of `f32`,
  for `--phy-rates` (`RNS/Utilities/rncp.py:331`).
- `RncpError` gains `Interrupted`, `NotFound`, `RemoteError`, `RequestFailed`
  and `Stamp`.
- `rnsh::RnshError` is `#[non_exhaustive]`. `Denied` carries the remote
  message, `Denied(String)`, and the enum gains `ClientException`, `LinkClosed`,
  `ProtocolError`, `StampFailure` and `Terminated`
  (`RNS/Utilities/rnsh/initiator.py:135-149`).
- `rns_protocol::rnsh::STREAM_DATA_OVERHEAD` is removed.
- The `rns-git` library (tier `tool-internal`, `publish = false`) is new. It
  supports `rngit-rs`, `git-remote-rns` and `rngcs-rs` and is not an
  integration API.

## RPC

`rpc::RpcRequest` gains variants for 1.6.0 shared-instance requests:

- `GetActiveLinkCount`, `GetLinkDistribution`, `GetLowestInterfaceBitrate`,
  `GetMediumPathTimeout` and `GetProfilingResults`;
- `ManageInterface`;
- `WantsDestinationType`, `UnwantsDestinationType` and
  `UnwantsAllDestinationTypes`.

`rpc::InterfaceStatEntry` and `PathTableEntry` gain the 1.6.0 stats fields.
Both implement `Default`; build them with `..Default::default()`.

## New fields and variants

Exhaustive literals and matches over these types need updating:

- **rns-transport:**
  - `InterfaceEntry`, `InterfaceStatRpcEntry`, `InterfaceInspectionSnapshot`,
    `PathTableRpcEntry`, `RecentAnnounce`, `TunnelPath`;
  - the persisted entries;
  - `TransportMessage`, `TransportQuery`, `TransportQueryResponse`,
    `SkipReason`.
- **rns-runtime:**
  - `InitOptions`, `ReticulumConfig`, `RecalledDestination`,
    `LinkConnectOptions`, `DestinationRuntimeOptions`, `InterfacePostInit`;
  - `LinkSessionConfig`, `LinkSessionResponse`, `LinkSessionReceivedResource`,
    `LinkSessionResourceReceipt`, `ResourceCompletion`, `RnshClientConfig`,
    `DestinationRequest`;
  - `LinkManagerCommand`, `ChannelSendError`, `LinkSessionError`,
    `LinkSessionResourceError`, `LinkClientError`, `RncpError`, `RpcRequest`,
    `RpcResponse`.
- **rns-link:** `Link`, `HandshakeError`, `LinkKeyError`.
- **rns-protocol:** `ResourceError`, `ResourceFlags`, `InboundTransfer`,
  `OutboundTransfer`, `MultiSegmentInbound`.
- **rns-interface:** TCP, Backbone, Local, RNode and BLE configs;
  `TcpInterfaceState`.

## Behaviour and configuration an operator sees

- **Strict config values for the new keys.** 1.4.0 already stopped start-up
  on an unparsable boolean or integer in `[reticulum]` and `[logging]`. The
  same rule now covers the new `[stamps]` section (`RNS/Reticulum.py:505-512`),
  the new `[filter]` section, and the keys added since 1.4.0:
  `egress_control`, `default_gravity`, `ic_max_held_announces`,
  `enable_interface_management`, `autoconnect_interface_gravity`,
  `required_discovery_value` and `discover_interfaces_required_value` (now a
  float). Each fails with `invalid value for [section] key`, because
  ConfigObj's `as_bool`/`as_int` raise (`RNS/Reticulum.py:508`, `:625`).
- **Interface start failures stop start-up.** An interface that fails to build
  or start (an occupied port, say) fails `init` and shuts down what started, as
  Python panics (`RNS/Reticulum.py:1306-1311`). Embedders that want the old
  behaviour set `InitOptions::keep_starting_after_interface_failure = true`
  and read `ReticulumHandle::startup_interface_failures()`.
  `panic_on_interface_error` still governs runtime driver errors.
- **Server interfaces accept after registration.** TCP, Backbone, Local and
  I2P servers accept connections only once the interface is registered with
  transport, so every accepted connection copies the interface's final
  settings. An embedder that builds a server interface and never registers it
  no longer accepts connections; there is no timeout.
- **Per-interface frequency keys are taken as written.** A negative
  `ic_burst_freq`, `ec_pr_freq` or similar key on an interface is no longer
  refused at load. As in upstream, it puts the interface into permanent
  limiting (`RNS/Reticulum.py:1001-1010`, `RNS/Interfaces/Interface.py:206`).
- **Stored files.**
  - Destination announce stamps persist as `<storage>/stamps/<hash>.dstamp`
    (`RNS/Stamps.py:869-875`) and are reused across restarts.
  - The announce cache and path table are written on upstream's save cadence.
  - Existing files are read unchanged.
- **Log levels.** Every tool and daemon uses Python's numeric levels.
  Without a `loglevel` key, `rnsd` now runs at Notice (3), not Info (4)
  (`RNS/__init__.py:63`, `:76`). At Notice, only notice-tagged info events
  appear, so a default `rnsd` log is quieter than 1.4.0's. 1.4.0 mapped levels
  3 and 4 both to `INFO`. Set `loglevel = 4` for the old volume. `rnsd`
  ignores `-v`/`-q` in service mode, as it did before.
- **Link MTU.** Links signal and adopt the next hop's hardware MTU when
  `link_mtu_discovery` is on. It is on by default (`RNS/Reticulum.py:105`,
  `RNS/Link.py:392-397`). Resources on such links use larger parts, and a
  transit node clamps the signalled MTU. Set `link_mtu_discovery = No` to keep
  the 500-byte link MTU.
- **Stamps.** With `[stamps]` keys or the `InitOptions` switches,
  destinations stamp announces, path requests and link requests. Enforcement
  drops unstamped traffic, as upstream does.
