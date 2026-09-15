"""Deterministic partition helpers for NetGuard AI dataset splits."""

from __future__ import annotations

import hashlib


TRAIN_CUTOFF = 0.70
VALIDATION_CUTOFF = 0.85


def partition_from_unit_interval(value: float) -> str:
    """Map a value in [0, 1) to the frozen 70/15/15 split intervals."""
    if not 0.0 <= value < 1.0:
        raise ValueError("value must be in the interval [0, 1)")
    if value < TRAIN_CUTOFF:
        return "train"
    if value < VALIDATION_CUTOFF:
        return "validation"
    return "test"


def random_partition(feature_hash: str, seed: int = 42) -> str:
    """Assign one feature-hash group reproducibly to train, validation, or test."""
    if len(feature_hash) != hashlib.sha256().digest_size * 2:
        raise ValueError("feature_hash must be a 64-character SHA-256 digest")
    try:
        fingerprint = bytes.fromhex(feature_hash)
    except ValueError as error:
        raise ValueError("feature_hash must be a hexadecimal SHA-256 digest") from error
    if len(fingerprint) != hashlib.sha256().digest_size:
        raise ValueError("feature_hash must be a 64-character SHA-256 digest")

    seeded_digest = hashlib.sha256(
        str(seed).encode("ascii") + b":" + fingerprint
    ).digest()
    numerator = int.from_bytes(seeded_digest[:8], byteorder="big", signed=False)
    unit_value = numerator / 2**64
    return partition_from_unit_interval(unit_value)
