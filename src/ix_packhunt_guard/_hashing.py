"""Deterministic hashing helpers for tamper-evident records."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from typing import Any

JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


def canonical_json(data: Mapping[str, Any] | Sequence[Any]) -> str:
    """Return stable JSON suitable for hashing and receipt comparison."""

    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    """Return a SHA-256 digest for text using UTF-8 encoding."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_record(data: Mapping[str, Any] | Sequence[Any]) -> str:
    """Return a SHA-256 digest for a canonical JSON record."""

    return sha256_text(canonical_json(data))


def hmac_sha256(secret: bytes, value: str) -> str:
    """Return an HMAC-SHA256 digest for privacy-preserving pseudonyms."""

    return hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()
