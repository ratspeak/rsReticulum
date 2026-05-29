# RatKey Hardware Status

RatKey hardware identity support is experimental. The runtime path (sign, ECDH,
decrypt, metadata pubkey read) is now validated on a real device; provisioning
on-device and attestation-chain verification are not yet implemented.

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
