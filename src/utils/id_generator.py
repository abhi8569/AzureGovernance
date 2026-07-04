"""Deterministic surrogate key generation for EAIP."""
from __future__ import annotations

import hashlib
import struct


def generate_surrogate_key(source_system: str, object_id: str) -> int:
    """Generate a deterministic 64-bit surrogate key.

    Uses SHA-256 hash of source_system + object_id, taking the first
    8 bytes as a signed int64. This ensures the same input always
    produces the same key.

    Args:
        source_system: Source system identifier (e.g., 'entra', 'azure_rbac').
        object_id: Object identifier from the source system.

    Returns:
        A deterministic int64 surrogate key.

    Note:
        Collision probability is ~1 in 2^63 per pair, acceptable
        for billions of records. If collisions are detected, add
        a salt or use a different hashing strategy.
    """
    combined = f"{source_system}:{object_id}"
    hash_bytes = hashlib.sha256(combined.encode("utf-8")).digest()
    # Unpack first 8 bytes as signed int64 (big-endian)
    key = struct.unpack(">q", hash_bytes[:8])[0]
    # Ensure positive (use absolute value)
    return abs(key)


def generate_composite_key(*parts: str) -> int:
    """Generate a deterministic key from multiple string parts.

    Args:
        *parts: String components to hash together.

    Returns:
        A deterministic int64 surrogate key.
    """
    combined = ":".join(parts)
    hash_bytes = hashlib.sha256(combined.encode("utf-8")).digest()
    key = struct.unpack(">q", hash_bytes[:8])[0]
    return abs(key)
