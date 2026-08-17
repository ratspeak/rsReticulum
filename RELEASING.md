# Source release policy

rsReticulum source releases are built from immutable Git history. A release is
identified by an annotated `vX.Y.Z` tag whose version matches the workspace
package version and a dated `X.Y.Z` section in `CHANGELOG.md`.

Before creating a tag:

1. Move the relevant `Unreleased` changelog entries into a dated version
   section.
2. Set the workspace version to that same semantic version.
3. Run `python3 scripts/ci/check_source_release_contract.py` and the normal CI
   suite with the committed `Cargo.lock`.
4. Create the tag only after the release commit is final. Published tags are
   immutable and must not be retargeted.

The release workflow checks out the requested existing tag, verifies that the
tag, manifest, changelog, and checked-out commit agree, and builds with
`--locked` on Rust 1.87.0. Release artifacts include this policy and the
changelog alongside the README and license.

All workspace packages are intentionally marked `publish = false`. Changing
that safeguard requires a separate package-distribution decision; a source
release does not change it.
