# RatKey Hardware Status

RatKey hardware identity support is **desktop only** and experimental. The full
desktop path is validated on a real YubiKey (5.7.4): provision (recoverable /
hardware-only / import / restore), on-card sign + ECDH, in-app load into LXMF/RNS,
PIN-prompt unlock, auto-lock timeout, and lock-on-quit. Attestation-chain
hardware-validation and pre-5.7 TDES management keys remain open.

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

### Software seed-restore (hardware-independent; cross-platform; not yet built)

Separate from the above and far simpler: a *recoverable* identity's 24-word
phrase can be restored as a plain **software** identity on any platform (incl.
mobile) — pure BIP-39 derivation (`seed::derive_identity`), no pcsc/NFC/USB. This
is the practical mobile recovery path ("I backed my YubiKey identity up on
desktop; restore it on my phone") **and** closes a gap on desktop today: the
existing "Restore from seed" only writes keys onto a *new YubiKey* (hardware
restore) — there is no restore-to-software path, so a lost key with no spare = no
recovery. Prerequisite: decouple the derivation from the `hardware`/pcsc feature
(`bip39`/`hkdf` are already non-optional in rns-ratkey; add a `seed` feature to
ratspeak-runtime that pulls `dep:rns-ratkey` *without* `rns-ratkey/hardware`, and
enable it on all platforms). Then a `restore_software_identity(phrase)` command
derives → builds a software `Identity` → saves it like import/create.

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
- `HardwareIdentity` decrypt end-to-end (on-device ECDH → HKDF → AES token).
- The pubkey our provision records matches ykman's independent export byte-for-byte.

## Still required before hardware RatKey is documented as supported

- **TDES management keys** are not supported (only AES-128/192/256). Pre-5.7
  YubiKeys default to a TDES management key; provisioning those needs a `des`
  block cipher added to `mgmt.rs`.
- Validate attestation-chain verification against a real device. `attestation.rs`
  now does full RSA PKCS#1 v1.5 chain verification (per-key → device F9 → bundled,
  fingerprint-pinned Yubico roots; legacy + new-PKI A/B/B2 intermediates bundled;
  notBefore/notAfter checks; no CRL/OCSP/name-constraints). Exercised against
  synthetic chains and the real published CA certs — not yet a physical YubiKey's
  ATTEST output.
- Edge cases on a real device: disconnect mid-operation, wrong PIN / lockout,
  touch timeout (if touch is ever enabled), and the `from_hwid` key-mismatch guard.
- Decide and document the ratchet policy for hardware identities. PIV cannot hold
  Reticulum ratchet private keys, so enforced-ratchet decrypt fails closed.
- Add hardware-gated tests that are skipped by default but run when a device is
  explicitly selected by environment/config.

Until those items pass on real devices, CLI/UI surfaces must label hardware
RatKey support as experimental.
