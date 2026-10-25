//! IFAC keys, and the masks derived from them, must not survive in freed heap
//! memory once a packet is signed or verified or an interface is dropped.

#[path = "../../rns-crypto/tests/residue/mod.rs"]
mod residue;

use std::collections::HashMap;

use residue::{assert_no_residue, freed_by, pseudo_random, serial};
use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_crypto::hkdf::hkdf_sha256;
use rns_identity::ifac::derive_ifac_key;
use rns_transport::constants::{InterfaceDirection, InterfaceMode};
use rns_transport::ifac::{ifac_sign, ifac_verify};
use rns_transport::messages::InterfaceEntry;

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

#[test]
fn an_interface_table_frees_no_ifac_keys() {
    let _serial = serial();
    let keys: Vec<[u8; 64]> = (0..48).map(|seed| pseudo_random(200 + seed)).collect();
    let (tx, _rx) = tokio::sync::mpsc::channel(1);

    // Growing the table moves every entry, so each key is moved several times.
    let ((), freed) = freed_by(|| {
        let mut interfaces = HashMap::new();
        for (id, key) in keys.iter().enumerate() {
            let entry = InterfaceEntry::new(
                format!("ifac-{id}"),
                InterfaceMode::Full,
                InterfaceDirection::bidirectional(),
                0,
                500,
                tx.clone(),
            )
            .with_ifac(*key, IFAC_SIZE);
            interfaces.insert(id as u64, entry);
        }
    });

    let secrets: Vec<(&str, &[u8])> = keys.iter().map(|key| ("IFAC key", &key[..])).collect();
    assert_no_residue(&freed, &secrets);
}
