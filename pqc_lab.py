"""
Post-Quantum Cryptography lab (educational / roadmap P3).

Provides narrative comparison and a software hash-based KEM *toy* for UI demos.
This is NOT a secure PQC implementation — clearly marked educational.
"""
from __future__ import annotations

import hashlib
import os
from typing import Dict, Tuple


PQC_ALGORITHMS = [
    {
        "name": "ML-KEM (Kyber)",
        "type": "KEM",
        "status": "NIST FIPS 203",
        "notes": "Lattice-based key encapsulation — primary PQC KEM standard.",
    },
    {
        "name": "ML-DSA (Dilithium)",
        "type": "Signature",
        "status": "NIST FIPS 204",
        "notes": "Lattice-based signatures for software authenticity.",
    },
    {
        "name": "SLH-DSA (SPHINCS+)",
        "type": "Signature",
        "status": "NIST FIPS 205",
        "notes": "Hash-based signatures — conservative assumption set.",
    },
    {
        "name": "Classic McEliece",
        "type": "KEM",
        "status": "Round-4 alternate",
        "notes": "Code-based; large public keys, long security track record.",
    },
]


def toy_hash_kem_keypair() -> Tuple[bytes, bytes]:
    """Educational toy: public = hash chain seed, secret = seed. NOT secure."""
    sk = os.urandom(32)
    pk = hashlib.sha3_256(b"MCL-TOY-KEM-PK" + sk).digest()
    return pk, sk


def toy_hash_kem_encaps(pk: bytes) -> Tuple[bytes, bytes]:
    """Returns (ciphertext, shared_secret)."""
    ephemeral = os.urandom(32)
    ct = hashlib.sha3_256(b"MCL-TOY-KEM-CT" + pk + ephemeral).digest() + ephemeral
    ss = hashlib.sha3_256(b"MCL-TOY-KEM-SS" + pk + ephemeral).digest()
    return ct, ss


def toy_hash_kem_decaps(sk: bytes, ct: bytes) -> bytes:
    if len(ct) < 64:
        raise ValueError("Invalid toy ciphertext")
    pk = hashlib.sha3_256(b"MCL-TOY-KEM-PK" + sk).digest()
    ephemeral = ct[32:]
    return hashlib.sha3_256(b"MCL-TOY-KEM-SS" + pk + ephemeral).digest()


def migration_checklist() -> list:
    return [
        {"item": "Inventory public-key usage (TLS, VPN, code signing, email)", "priority": "P0"},
        {"item": "Prefer hybrid classical+PQC during transition", "priority": "P0"},
        {"item": "Plan for larger keys/ciphertexts in protocols and UI", "priority": "P1"},
        {"item": "Track NIST FIPS 203/204/205 library support in stack", "priority": "P1"},
        {"item": "Re-test performance on constrained devices", "priority": "P2"},
    ]
