# API stability

rsReticulum is currently distributed as source with `publish = false`. Its
package versions describe protocol/source compatibility; they do not mean that
every reachable Rust item is already a permanent stable API.

`api-stability.json` is the machine-readable package ledger. The corresponding
`api-baseline/*.txt` files record every explicit public item visible with all
features on the canonical Apple ARM64 rustdoc target. CI regenerates those
snapshots with exact `cargo-public-api` and nightly versions. A diff is a review
barrier, not an automatic verdict: additions, removals, and signature changes
must be classified before a snapshot is deliberately updated.

## Tiers

- **Candidate stable:** intended protocol or integration surface, but not yet a
  final SemVer promise. Compatibility is the default while boundaries are
  curated.
- **Provisional:** externally reachable low-level or mixed surface. Consumers
  may use it, but boundary work and a migration decision are still required.
- **Experimental:** incomplete or optional surface that may change with an
  explicit version and changelog decision.
- **Tool internal:** support code for repository binaries, not a library API
  commitment.

The package ledger currently classifies `rns-identity`, `rns-link`,
`rns-protocol`, and `rns-interface` as candidate stable. `rns-crypto`,
`rns-wire`, and `rns-transport` remain provisional low-level packages.
`rns-runtime` is also provisional because it mixes the intended application
facade (`rns_runtime::prelude`, lifecycle handles, destination resolution, and
Link sessions) with broad actor, RPC, manager, and command modules. `rns-ratkey`
is experimental, and the `rns-tools` library target is tool internal.

The existing [`rns_runtime::prelude`](APPLICATION_API.md) is the canonical
application spine. It re-exports the original type identities, and all current
module-qualified paths remain supported. Actor, mailbox, RPC, transport-table,
concrete-driver, and endpoint-ownership modules remain provisional SPI; their
reachability in a snapshot does not promote them.

No existing module is hidden, moved, or made private by this baseline. That
work requires the next explicit API-boundary checkpoint, downstream migration
evidence from rsLXMF/rsLXST/Ratspeak, and a versioning decision.

## Baseline scope and use

The canonical snapshot is all-features `aarch64-apple-darwin`. It intentionally
omits auto-derived, auto-trait, and blanket implementations to keep diffs
reviewable. Target-only Linux, Android, and Windows overlays remain protected
by their existing compile, package, and integration gates; they are not yet a
stable cross-target Rust API promise.

To verify the baseline:

```sh
cargo install cargo-public-api --version 0.52.0 --locked
rustup toolchain install nightly-2026-08-01 --profile minimal
python3 tools/check-api-baseline.py
python3 tools/check-api-manifest.py
python3 tools/check-api-compatibility.py
cargo check --manifest-path api-fixtures/Cargo.toml --locked
cargo check --manifest-path api-fixtures/Cargo.toml --all-features --locked
```

The immutable floor and current captured snapshot source are separate
identities in `api-stability.json`. The compatibility check currently enforces
an additions-only Wave C policy. Snapshot equality remains only one layer of
SemVer evidence: feature/cfg contracts, external fixtures, platform builds,
and behavioral tests remain mandatory.

Use `--update` only after reviewing the generated API diff and recording the
compatibility/version decision. Snapshot updates do not by themselves make a
breaking change acceptable.
