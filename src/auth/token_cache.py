"""Persistent MSAL token cache management."""
from __future__ import annotations

import json
import os
from pathlib import Path

import msal
import structlog

logger = structlog.get_logger(__name__)

DEFAULT_CACHE_PATH = "./data/.token_cache.json"


def load_cache(cache_path: str = DEFAULT_CACHE_PATH) -> msal.SerializableTokenCache:
    """Load token cache from disk.

    Args:
        cache_path: Path to the cache file.

    Returns:
        A SerializableTokenCache instance, populated if file exists.
    """
    cache = msal.SerializableTokenCache()
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache.deserialize(f.read())
            logger.debug("token_cache_loaded", path=cache_path)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("token_cache_load_failed", path=cache_path, error=str(e))
    else:
        logger.debug("token_cache_not_found", path=cache_path)
    return cache


def save_cache(cache: msal.SerializableTokenCache, cache_path: str = DEFAULT_CACHE_PATH) -> None:
    """Save token cache to disk.

    Args:
        cache: The token cache to persist.
        cache_path: Path to write the cache file.
    """
    if cache.has_state_changed:
        try:
            cache_dir = os.path.dirname(cache_path)
            if cache_dir:
                os.makedirs(cache_dir, exist_ok=True)
            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(cache.serialize())
            logger.debug("token_cache_saved", path=cache_path)
        except OSError as e:
            logger.error("token_cache_save_failed", path=cache_path, error=str(e))
