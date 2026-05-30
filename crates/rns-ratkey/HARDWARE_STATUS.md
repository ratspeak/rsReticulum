# RatKey Hardware Status

RatKey hardware identity support is **desktop only** and experimental. The full
desktop path is validated on a real YubiKey (5.7.4): provision (recoverable /
hardware-only / import / restore), on-card sign + ECDH, in-app load into LXMF/RNS,
PIN-prompt unlock, auto-lock timeout, lock-on-quit, and **attestation-chain
verification against the device's real ATTEST output**. Pre-5.7 (TDES) management
keys are implemented and unit-tested but await validation on a pre-5.7 device.

## Release scope: desktop only

Mobile is intentionally excluded from release. The `hardware` feature is off on
iOS/Android (pcsc is desktop-only), the `hw_*` commands are
`#[cfg(not(any(target_os = "android", target_os = "ios")))]`, and the frontend
hides every hardware entry point on mobile (`isMobile()` gate in setup.js +
identity.js).

## Mobile (deferred — needs a different model)

Desktop keeps the token plugged in and does every sign/ECDH on-card. That can't
work over transient NFC (iOS CoreNFC is modal ~60s; Android IsoDep only while the
tag is in-field; neither runs in the background). A messaging app used all day
needs a **wrapped software session**: tap the key to unlock (on-card ECDH unwraps
a software identity stored encrypted at rest, ideally in the Secure Enclave /
StrongBox), operate in software for a configurable window (mirrors the desktop
auto-lock setting), re-tap to refresh. This is a different security model than
"key never leaves the token" and should be an explicit mode alongside
hardware-only. The `PivTransport` seam is ready (`PivSession::new` takes any
transport); a mobile loader belongs in `ratspeak-runtime`. Android NFC (IsoDep)
is the tractable first transport.

### Recoverable software identities — DONE (2026-05-29, cross-platform)

The recoverable model generalized "hardware identity" → "recoverable identity,"
with the YubiKey as one optional backing. All on every platform (the derivation
+ vault are pure-Rust, gated behind a default `seed` feature in ratspeak-runtime
that pulls `rns-ratkey` without pcsc):

- **Software seed-restore** (`ratspeak_runtime::derive_identity_key_from_phrase`,
  `restore_seed_identity` command): a 12-word phrase restores a software identity
  on any platform — the practical mobile recovery path. Folded into the app's
  **Import** flow (key *or* phrase), not a separate button.
- **Mnemonic-derived-by-default** (`generate_recoverable_key`): new software
  identities are derived from a fresh BIP-39 mnemonic shown for backup at creation.
  Both `api_create_identity` (settings) and `api_setup_complete` (first-setup)
  produce them; legacy random identities keep raw-key export.
  `LxmfManager::create_identity` (random) stays for internal/tests.
- **Recovery-phrase re-display** (`vault::store_plaintext_seed` /
  `has_stored_mnemonic` / `reveal_mnemonic`, `reveal_identity_mnemonic` command,
  software only): the phrase is persisted so it can be shown again. Its at-rest
  protection tracks the key's — a plaintext `identity.seed` sidecar when the
  identity is unprotected (crypto-equivalent to the already-plaintext `identity`
  key file), folded into the vault as a `mnemonic_token` (same KEK) once a passcode
  is set. The vault is authoritative when present, so reveal honors the passcode
  even if a stale sidecar survives the verify-before-delete window. Captured at
  create/import (both `api_create_identity`, `api_setup_complete`, and
  `restore_seed_identity`); hardware identities never store a phrase.
- **Passcode at-rest encryption** (`vault.rs`): software identities can be sealed
  with a passcode — Argon2id(passcode,salt) → HKDF(info=params‖salt) binds the KDF
  params → 64-byte KEK → `rns_crypto::token` (AES-256-CBC + HMAC). Stored as
  `identity.enc`; param-tamper/wrong-passcode → auth failure (unit-tested). The
  launch unlock + auto-lock + lock-on-quit machinery is shared with the hardware
  PIN path (one "protected identity" state, a `kind` discriminator selects PIN vs
  passcode; the `hw_unlock`/`hardware_locked`/`hw_locked` wire names are retained).

Caveat documented to users: restore recovers the *identity*, not past message
history (forward secrecy).

## Architecture (done)

- `PivTransport` is the platform seam: APDU bytes in, response bytes out.
  `PivSession<T>` builds every PIV operation on `apdu` over that seam and is
  transport-agnostic (compiles with no features).
- `PcscTransport` (behind the `hardware` feature) is the desktop PC/SC
  implementation; `PivSession::<PcscTransport>::connect()` is the entry point.
  Mobile NFC/USB transports implement `PivTransport` from the application layer.
- `HardwareIdentity` holds a `Box<dyn IdentityBackend>`, implemented by both
  `PivSession<T>` (real token, any transport) and `MockPivSession`.
- `PivSession::lock()` / `HardwareIdentity::lock()` re-select the PIV applet to
  drop the on-card PIN cache (mechanism for app-side session timeout / lock-on-quit).

## Validated on hardware (YubiKey 5, firmware 5.7.4)

Full provision → verify → test loop with our own code, PIN-once + touch-never
Ed25519 (9A) / X25519 (9D):

- **Management-key authentication** (witness/challenge, AES-192) — `hw provision`
  authenticates slot 9B and generates both keys on-device. Successful generate
  is proof of auth.
- `parse_metadata_public_key` reads the correct pubkey from GET METADATA
  (confirmed against ykman-exported ground truth — the layout assumption held).
- Ed25519 signing on slot 9A; signature verifies against the slot pubkey.
- X25519 ECDH on slot 9D; shared secret symmetric with a software peer.
- `HardwareIdentity` decrypt end-to-end (on-device ECDH → HKDF → AES token) — the
  same Ed25519-sign + X25519-ECDH + token-AES primitives LXMF uses, so live LXMF
  send/receive on a hardware identity routes through the card (serial 35284666).
- The pubkey our provision records matches ykman's independent export byte-for-byte.
- **Attestation chain verified against the device's real ATTEST output** (`hw
  attest`): both slot-9A/9D per-key certs chain through the slot-F9 device
  intermediate to a bundled, fingerprint-pinned new-PKI Yubico root. `hw provision`
  now captures + verifies the chain into the `.hwid`. The captured 5.7.4 certs are
  committed as a CI regression vector (`tests/fixtures/{9a_attest,f9_device}.der`).

## Still required before hardware RatKey is documented as supported

- **TDES management keys** are implemented (3DES EDE3 via the `des` crate, 8-byte
  block; `mgmt.rs` dispatches on the algorithm byte). A FIPS-81 known-answer test
  and a distinct-subkey round-trip cover the cipher. Pre-5.7 YubiKeys default to a
  TDES management key; the witness/challenge auth flow already drives its block
  size from `mgmt::block_len`, so it is ready — but not yet exercised against a
  physical pre-5.7 device.
- A two-node **live LXMF message exchange** in the app on a hardware identity. The
  on-card crypto primitives are validated (above) and the runtime delegates
  sign/ECDH to the backend, but an end-to-end app round-trip between two peers is
  still a manual check.
- Edge cases on a real device: disconnect mid-operation, wrong PIN / lockout,
  touch timeout (if touch is ever enabled), and the `from_hwid` key-mismatch guard.
- Decide and document the ratchet policy for hardware identities. PIV cannot hold
  Reticulum ratchet private keys, so enforced-ratchet decrypt fails closed.
- Add hardware-gated tests that are skipped by default but run when a device is
  explicitly selected by environment/config.

Until those items pass on real devices, CLI/UI surfaces must label hardware
RatKey support as experimental.
