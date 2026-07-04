from __future__ import annotations

import os
from typing import Any

from fastapi import Header, HTTPException, Request


def _expected_key() -> str:
    key = os.getenv("INTERNAL_API_KEY")
    if not key:
        raise RuntimeError("INTERNAL_API_KEY is required.")
    return key


def require_internal_api_key(x_internal_api_key: str | None = Header(default=None)) -> None:
    expected = _expected_key()
    if x_internal_api_key != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


def _split_csv(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def enforce_source_ip(request: Request) -> None:
    allowed = _split_csv(os.getenv("RELATIONSHIP_API_IPS"))
    if not allowed:
        return
    client_host = request.client.host if request.client else None
    if client_host not in allowed:
        raise HTTPException(status_code=403, detail="Source IP not allowed")


def approval_context(approved_by: str | None, approval_level: str | None) -> dict[str, Any]:
    return {
        "approved_by": approved_by,
        "approval_level": approval_level,
    }

