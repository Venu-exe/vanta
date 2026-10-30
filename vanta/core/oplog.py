"""Append-only operations log.

A red team lives or dies by its operational record: what ran, against what, when,
and with what result. VANTA writes newline-delimited JSON so the log can be
tail-ed live, grepped, or shipped straight into a SIEM. Secrets are redacted
before they hit disk.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

_REDACT_PATTERNS = [
    re.compile(r"(?i)(authorization:\s*)(\S+\s+)?(\S+)"),
    re.compile(r"(?i)(cookie:\s*)(.+)"),
    re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)([\"'=:\s]+)([^\s\"',&]+)"),
]


def redact(text: str) -> str:
    """Best-effort secret scrubbing for log lines."""
    if not text:
        return text
    out = text
    out = _REDACT_PATTERNS[0].sub(lambda m: f"{m.group(1)}[REDACTED]", out)
    out = _REDACT_PATTERNS[1].sub(lambda m: f"{m.group(1)}[REDACTED]", out)
    out = _REDACT_PATTERNS[2].sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", out)
    return out


class OpsLog:
    """Structured, timestamped, append-only JSONL log."""

    LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}

    def __init__(
        self,
        path: str | Path | None = None,
        level: str = "info",
        echo: bool = True,
    ) -> None:
        self.path = Path(path) if path else None
        self.level = level.lower()
        self.threshold = self.LEVELS.get(self.level, 20)
        self.echo = echo
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Fresh log per run keeps evidence trails unambiguous.
            self.path.write_text("", encoding="utf-8")

    def _write(self, level: str, event: str, **fields: Any) -> None:
        if self.LEVELS[level] < self.threshold:
            return
        record = {"ts": round(time.time(), 3), "level": level, "event": event}
        record.update({k: redact(str(v)) if isinstance(v, str) else v for k, v in fields.items()})
        line = json.dumps(record, default=str)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        if self.echo:
            marker = {"debug": "·", "info": "→", "warn": "!", "error": "✗"}[level]
            detail = " ".join(f"{k}={v}" for k, v in fields.items() if v not in (None, ""))
            print(f"  {marker} [{level}] {event} {detail}".rstrip())

    def debug(self, event: str, **f: Any) -> None:
        self._write("debug", event, **f)

    def info(self, event: str, **f: Any) -> None:
        self._write("info", event, **f)

    def warn(self, event: str, **f: Any) -> None:
        self._write("warn", event, **f)

    def error(self, event: str, **f: Any) -> None:
        self._write("error", event, **f)
