//! IFAC masks, derived from the interface key, must not survive in freed heap
//! memory once a packet is signed or verified.

#[path = "../../rns-crypto/tests/residue/mod.rs"]
mod residue;

use residue::{assert_no_residue, freed_by, pseudo_random, serial};
use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_crypto::hkdf::hkdf_sha256;
use rns_identity::ifac::derive_ifac_key;
use rns_transport::ifac::{ifac_sign, ifac_verify};

const IFAC_SIZE: usize = 16;

fn packet() -> Vec<u8> {
    let mut packet = pseudo_random::<120>(30).to_vec();
    packet[0] &= 0x7f;
    packet
}

fn mask(ifac_key: &[u8; 64], tag: &[u8], len: usize) -> Vec<u8> {
    hkdf_sha256(len, tag, Some(ifac_key), None).unwrap()[..].to_vec()
}

#[test]
fn ifac_sign_frees_no_mask() {
    let _serial = serial();
    let ifac_key = derive_ifac_key(Some("residue"), Some("mask")).unwrap();
    let packet = packet();
    let signature = Ed25519PrivateKey::from_bytes(ifac_key[32..].try_into().unwrap()).sign(&packet);
    let mask = mask(
        &ifac_key,
        &signature[64 - IFAC_SIZE..],
        packet.len() + IFAC_SIZE,
    );

    let (signed, freed) = freed_by(|| ifac_sign(&packet, &ifac_key, IFAC_SIZE));

    assert_no_residue(&freed, &[("IFAC mask", &mask)]);
    assert_eq!(ifac_verify(&signed, &ifac_key, IFAC_SIZE).unwrap(), packet);
}

#[test]
fn ifac_verify_frees_no_mask() {
    let _serial = serial();
    let ifac_key = derive_ifac_key(Some("residue"), Some("mask")).unwrap();
    let packet = packet();
    let signed = ifac_sign(&packet, &ifac_key, IFAC_SIZE);
    let mask = mask(&ifac_key, &signed[2..2 + IFAC_SIZE], signed.len());

    let (verified, freed) = freed_by(|| ifac_verify(&signed, &ifac_key, IFAC_SIZE));

    assert_no_residue(&freed, &[("IFAC mask", &mask)]);
    assert_eq!(verified.unwrap(), packet);
}
