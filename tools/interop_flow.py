#!/usr/bin/env python3
"""
Generate interop artifacts for Rust validation.

Exercises the full RNS + LXMF identity/announce/message/stamp stack using
deterministic seeds (no randomness) so that artifacts are reproducible.
Writes files to interop_artifacts/ directory.

Usage:
    python3 tools/interop_flow.py
    # Then run the maintainer artifact-validation checks.
"""

import hashlib
import hmac as hmac_mod
import json
import os
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

import msgpack


# ---------------------------------------------------------------------------
# Crypto primitives (reused from generate_vectors.py)
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac_mod.new(key, data, hashlib.sha256).digest()


def hkdf_sha256(length: int, ikm: bytes, salt: bytes | None, info: bytes | None) -> bytes:
    h = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info if info is not None else b"",
    )
    return h.derive(ikm)


def hex_str(data: bytes) -> str:
    return data.hex()


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def x25519_from_seed(seed_32: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(seed_32)


def ed25519_from_seed(seed_32: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed_32)


def x25519_pub_bytes(prv: X25519PrivateKey) -> bytes:
    return prv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def ed25519_pub_bytes(prv: Ed25519PrivateKey) -> bytes:
    return prv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def x25519_prv_bytes(prv: X25519PrivateKey) -> bytes:
    return prv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def ed25519_prv_bytes(prv: Ed25519PrivateKey) -> bytes:
    return prv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


# ---------------------------------------------------------------------------
# Reticulum hash helpers
# ---------------------------------------------------------------------------

def name_hash(app_name: str) -> bytes:
    """SHA-256(app_name)[:10] -- matches Reticulum name_hash."""
    return sha256(app_name.encode("utf-8"))[:10]


def identity_hash(public_key_64: bytes) -> bytes:
    """SHA-256(public_key_64)[:16] -- truncated identity hash."""
    return sha256(public_key_64)[:16]


def dest_hash_single(name_hash_bytes: bytes, id_hash: bytes) -> bytes:
    """SHA-256(name_hash || identity_hash)[:16]."""
    return sha256(name_hash_bytes + id_hash)[:16]


# ---------------------------------------------------------------------------
# Artifact directory
# ---------------------------------------------------------------------------

ARTIFACTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "interop_artifacts",
)


def write_artifact(name: str, data: bytes) -> str:
    """Write binary artifact file. Returns the path."""
    path = os.path.join(ARTIFACTS_DIR, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


# ---------------------------------------------------------------------------
# 1. Identity artifact
# ---------------------------------------------------------------------------

def generate_identity():
    """Generate a deterministic identity from fixed seeds."""
    x_seed = sha256(b"interop_x25519_seed")
    ed_seed = sha256(b"interop_ed25519_seed")

    x_prv = x25519_from_seed(x_seed)
    ed_prv = ed25519_from_seed(ed_seed)

    x_pub = x25519_pub_bytes(x_prv)
    ed_pub = ed25519_pub_bytes(ed_prv)
    public_key_64 = x_pub + ed_pub
    id_hash = identity_hash(public_key_64)

    # Also compute private key in Reticulum format: x25519_prv(32) || ed25519_seed(32)
    private_key_64 = x25519_prv_bytes(x_prv) + ed25519_prv_bytes(ed_prv)

    identity_data = {
        "x25519_seed": hex_str(x_seed),
        "ed25519_seed": hex_str(ed_seed),
        "x25519_private": hex_str(x25519_prv_bytes(x_prv)),
        "ed25519_private": hex_str(ed25519_prv_bytes(ed_prv)),
        "x25519_public": hex_str(x_pub),
        "ed25519_public": hex_str(ed_pub),
        "public_key_64": hex_str(public_key_64),
        "identity_hash": hex_str(id_hash),
        "private_key_64": hex_str(private_key_64),
    }

    # Write identity.json
    with open(os.path.join(ARTIFACTS_DIR, "identity.json"), "w") as f:
        json.dump(identity_data, f, indent=2)

    return x_prv, ed_prv, x_pub, ed_pub, public_key_64, id_hash, identity_data


# ---------------------------------------------------------------------------
# 2. Announce artifact
# ---------------------------------------------------------------------------

def generate_announce(x_pub, ed_pub, ed_prv, public_key_64, id_hash):
    """Create a deterministic announce, sign it, and write artifacts."""
    app_name = "lxmf.delivery"
    app_data = b"Interop test announce"

    nh = name_hash(app_name)
    dest_hash = dest_hash_single(nh, id_hash)

    # Deterministic random hash (normally random(5) + timestamp(5))
    random_hash = sha256(b"interop_random_hash_seed")[:10]

    # Build signed data: dest_hash + public_key + name_hash + random_hash + app_data
    signed_data = bytearray()
    signed_data.extend(dest_hash)
    signed_data.extend(public_key_64)
    signed_data.extend(nh)
    signed_data.extend(random_hash)
    signed_data.extend(app_data)

    signature = ed_prv.sign(bytes(signed_data))

    # Pack announce (without ratchet):
    # public_key(64) || name_hash(10) || random_hash(10) || signature(64) || app_data
    packed = bytearray()
    packed.extend(public_key_64)
    packed.extend(nh)
    packed.extend(random_hash)
    packed.extend(signature)
    packed.extend(app_data)

    write_artifact("announce.bin", bytes(packed))

    announce_data = {
        "app_name": app_name,
        "app_data": hex_str(app_data),
        "name_hash": hex_str(nh),
        "dest_hash": hex_str(dest_hash),
        "random_hash": hex_str(random_hash),
        "signed_data": hex_str(bytes(signed_data)),
        "signature": hex_str(signature),
        "packed_length": len(packed),
        "has_ratchet": False,
    }

    with open(os.path.join(ARTIFACTS_DIR, "announce.json"), "w") as f:
        json.dump(announce_data, f, indent=2)

    return announce_data


# ---------------------------------------------------------------------------
# 3. LXMF Message artifact
# ---------------------------------------------------------------------------

def generate_lxmf_message(ed_prv, id_hash):
    """Create a deterministic LXMF message, sign it, and write artifacts."""
    # Source identity is the interop identity
    app_name = "lxmf.delivery"
    nh = name_hash(app_name)
    src_hash = dest_hash_single(nh, id_hash)

    # Destination: use a second deterministic identity
    dest_x_seed = sha256(b"interop_dest_x25519_seed")
    dest_ed_seed = sha256(b"interop_dest_ed25519_seed")
    dest_x_prv = x25519_from_seed(dest_x_seed)
    dest_ed_prv = ed25519_from_seed(dest_ed_seed)
    dest_x_pub = x25519_pub_bytes(dest_x_prv)
    dest_ed_pub = ed25519_pub_bytes(dest_ed_prv)
    dest_public_key_64 = dest_x_pub + dest_ed_pub
    dest_id_hash = identity_hash(dest_public_key_64)
    dest_hash = dest_hash_single(nh, dest_id_hash)

    timestamp = 1700000000.0
    title = "Interop Test"
    content = "Hello from Python interop!"

    # Fields: image field (0x06) with small test data
    fields = {0x06: b"\xde\xad\xbe\xef"}

    # Pack payload: msgpack([timestamp, title_bytes, content_bytes, fields_map])
    # Title and content are packed as bytes (bin type), not strings
    payload = msgpack.packb(
        [timestamp, title.encode("utf-8"), content.encode("utf-8"), fields],
        use_bin_type=True,
    )

    # Sign: signed_data = dest_hash + src_hash + payload + SHA256(dest_hash + src_hash + payload)
    signed_data = bytearray()
    signed_data.extend(dest_hash)
    signed_data.extend(src_hash)
    signed_data.extend(payload)
    message_hash = sha256(bytes(signed_data))
    signed_data.extend(message_hash)

    signature = ed_prv.sign(bytes(signed_data))

    # Pack wire format: dest_hash(16) + src_hash(16) + signature(64) + payload
    packed = bytearray()
    packed.extend(dest_hash)
    packed.extend(src_hash)
    packed.extend(signature)
    packed.extend(payload)

    write_artifact("lxmf_message.bin", bytes(packed))

    # Compute full message hash (SHA-256 of packed)
    full_hash = sha256(bytes(packed))

    lxmf_data = {
        "dest_hash": hex_str(dest_hash),
        "src_hash": hex_str(src_hash),
        "dest_identity_hash": hex_str(dest_id_hash),
        "timestamp": timestamp,
        "title": title,
        "content": content,
        "field_image": hex_str(b"\xde\xad\xbe\xef"),
        "payload": hex_str(payload),
        "message_hash": hex_str(message_hash),
        "signed_data": hex_str(bytes(signed_data)),
        "signature": hex_str(signature),
        "packed_length": len(packed),
        "full_hash": hex_str(full_hash),
        "ed25519_public": hex_str(ed25519_pub_bytes(ed_prv)),
    }

    with open(os.path.join(ARTIFACTS_DIR, "lxmf_message.json"), "w") as f:
        json.dump(lxmf_data, f, indent=2)

    return lxmf_data


# ---------------------------------------------------------------------------
# 4. Stamp artifact
# ---------------------------------------------------------------------------

def generate_stamp():
    """Generate a deterministic stamp workblock and find a valid stamp."""
    # Use a known message_id
    message_id = sha256(b"interop_stamp_message_id")
    cost = 4  # Low cost so we can find it quickly

    # Compute workblock using iterative SHA-256 (matching Rust stamp_workblock)
    expand_rounds = 3000
    current = message_id
    for _ in range(expand_rounds):
        current = sha256(current)
    workblock = current

    # Brute-force search for a valid stamp
    import random
    rng = random.Random(42)  # Deterministic PRNG for reproducibility
    stamp = None
    attempts = 0
    while True:
        candidate = bytes(rng.getrandbits(8) for _ in range(32))
        attempts += 1

        # Check: SHA-256(workblock + candidate) must have >= cost leading zero bits
        check = sha256(workblock + candidate)
        # Count leading zero bits
        leading_zeros = 0
        for byte in check:
            if byte == 0:
                leading_zeros += 8
            else:
                leading_zeros += (byte).bit_length()
                leading_zeros = (leading_zeros - (byte).bit_length())
                # Actually count leading zeros of the byte
                lz = 0
                for bit_pos in range(7, -1, -1):
                    if byte & (1 << bit_pos):
                        break
                    lz += 1
                leading_zeros = leading_zeros - lz + lz  # Fix the count
                break

        # Simpler approach: recompute properly
        check_val = int.from_bytes(check, "big")
        if check_val <= (1 << (256 - cost)):
            stamp = candidate
            stamp_value = 256 - check_val.bit_length()
            break

    stamp_data = {
        "message_id": hex_str(message_id),
        "cost": cost,
        "expand_rounds": expand_rounds,
        "workblock": hex_str(workblock),
        "stamp": hex_str(stamp),
        "stamp_value": stamp_value,
        "attempts": attempts,
        "check_hash": hex_str(sha256(workblock + stamp)),
    }

    with open(os.path.join(ARTIFACTS_DIR, "stamp.json"), "w") as f:
        json.dump(stamp_data, f, indent=2)

    return stamp_data


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)

    print(f"Writing interop artifacts to {ARTIFACTS_DIR}/")

    # 1. Identity
    x_prv, ed_prv, x_pub, ed_pub, public_key_64, id_hash, identity_data = generate_identity()
    print(f"  identity.json     (hash: {identity_data['identity_hash'][:16]}...)")

    # 2. Announce
    announce_data = generate_announce(x_pub, ed_pub, ed_prv, public_key_64, id_hash)
    print(f"  announce.json/bin (dest: {announce_data['dest_hash'][:16]}...)")

    # 3. LXMF Message
    lxmf_data = generate_lxmf_message(ed_prv, id_hash)
    print(f"  lxmf_message.json/bin (hash: {lxmf_data['message_hash'][:16]}...)")

    # 4. Stamp
    stamp_data = generate_stamp()
    print(f"  stamp.json        (value: {stamp_data['stamp_value']}, attempts: {stamp_data['attempts']})")

    # 5. Write manifest
    manifest = {
        "generator": "tools/interop_flow.py",
        "description": "Python-generated artifacts for Rust validation",
        "identity": identity_data,
        "announce": announce_data,
        "lxmf_message": lxmf_data,
        "stamp": stamp_data,
    }
    with open(os.path.join(ARTIFACTS_DIR, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    print("\n  manifest.json written. Run the maintainer artifact-validation checks next.")


if __name__ == "__main__":
    main()
