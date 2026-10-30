"""Asset discovery helpers shared by recon modules."""

from __future__ import annotations

import socket
from pathlib import Path

_DATA = Path(__file__).resolve().parents[2] / "data"


def load_lines(name: str, limit: int | None = None) -> list[str]:
    path = _DATA / name
    if not path.exists():
        return []
    lines = [
        ln.strip()
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    return lines[:limit] if limit else lines


async def resolve(host: str) -> list[str]:
    """Resolve a hostname to IPs without blocking the event loop."""
    import asyncio

    def _resolve() -> list[str]:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return []
        return sorted({info[4][0] for info in infos})

    return await asyncio.to_thread(_resolve)


async def resolves(host: str) -> bool:
    return bool(await resolve(host))
