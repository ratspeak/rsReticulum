mod support;

use std::path::Path;

use rns_runtime::prelude::*;
use support::*;

const ASPECT: &str = "example_utilities.ratchet.echo.request";

fn load_or_create_identity(path: &Path) -> ExampleResult<Identity> {
    if path.exists() {
        return Ok(Identity::from_file(path)?);
    }
    let identity = Identity::new();
    identity.to_file(path)?;
    Ok(identity)
}

fn load_or_create_ring(path: &Path, identity: &Identity) -> ExampleResult<PersistentRatchetRing> {
    let mut ring = PersistentRatchetRing::open(path, identity)?;
    ring.ensure_current(identity)?;
    Ok(ring)
}

fn main() -> ExampleResult {
    let args = ExampleArgs::parse()?;
    let identity_path = Path::new(args.require(0, "identity file")?);
    let ratchet_path = Path::new(args.require(1, "ratchet file")?);
    let message = args
        .positional
        .get(2)
        .map_or("Forward-secret message", String::as_str);

    let identity = load_or_create_identity(identity_path)?;
    let ring = load_or_create_ring(ratchet_path, &identity)?;
    let ratchet = ring
        .current_public_key()
        .ok_or("ratchet ring has no current key")?;

    let mut inbound = Destination::new(Some(&identity), Direction::In, DestType::Single, ASPECT)?;
    inbound.enable_ratchets(true);
    inbound.set_local_ratchet(ratchet);
    let announce = inbound.announce_packet(
        &identity,
        Some(b"ratchet example"),
        inbound.get_ratchet_for_announce().as_ref(),
        false,
        None,
        0.0,
    )?;

    let remote_identity = Identity::from_public_key(&identity.get_public_key())?;
    let mut outbound = Destination::new(
        Some(&remote_identity),
        Direction::Out,
        DestType::Single,
        ASPECT,
    )?;
    outbound.set_remote_ratchet(ratchet);
    let ciphertext = outbound.encrypt(
        message.as_bytes(),
        &remote_identity,
        outbound.remote_ratchet_pub.as_ref(),
    )?;
    let plaintext =
        inbound.decrypt_with_ratchets(&ciphertext, &identity, Some(ring.private_keys()))?;

    println!("Destination: {}", hex::encode(inbound.hash));
    println!("Retained ratchets: {}", ring.len());
    println!("Signed announce: {} bytes", announce.len());
    println!("Decrypted: {}", String::from_utf8_lossy(&plaintext));
    Ok(())
}
