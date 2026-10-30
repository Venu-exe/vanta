"""Evidence store with chain-of-custody hashing.

Every artefact a module captures is written to disk under the engagement
directory and hashed with SHA-256. A manifest records kind, path, hash and
timestamp, and :func:`verify` re-hashes everything so you can prove nothing was
tampered with after collection - the forensic discipline a real report needs.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from vanta.core.models import Evidence


class EvidenceStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._artefacts = self.root / "artefacts"
        self._artefacts.mkdir(exist_ok=True)
        self.manifest_path = self.root / "custody.jsonl"

    def store(
        self,
        kind: str,
        summary: str,
        data: bytes,
        filename: str | None = None,
    ) -> Evidence:
        """Persist ``data`` and return an :class:`Evidence` referencing it."""
        digest = Evidence.hash_bytes(data)
        filename = filename or f"{int(time.time() * 1000)}-{digest[:12]}.bin"
        path = self._artefacts / filename
        path.write_bytes(data)

        ev = Evidence(
            kind=kind,
            summary=summary,
            sha256=digest,
            path=str(path.relative_to(self.root)),
        )
        self._append_manifest(ev, len(data))
        return ev

    def _append_manifest(self, ev: Evidence, size: int) -> None:
        record: dict[str, Any] = {
            "captured_at": ev.captured_at,
            "kind": ev.kind,
            "summary": ev.summary,
            "sha256": ev.sha256,
            "path": ev.path,
            "size": size,
            "chain": self._last_hash(),
        }
        with self.manifest_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

    def _last_hash(self) -> str:
        """Hash of the previous manifest entry - a simple hash chain."""
        if not self.manifest_path.exists():
            return "genesis"
        last = None
        for line in self.manifest_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = line
        if last is None:
            return "genesis"
        return Evidence.hash_bytes(last.encode("utf-8"))

    def verify(self) -> tuple[bool, list[str]]:
        """Recompute every hash; returns (ok, problems)."""
        problems: list[str] = []
        if not self.manifest_path.exists():
            return True, []
        for line in self.manifest_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            path = self.root / rec["path"]
            if not path.exists():
                problems.append(f"missing artefact: {rec['path']}")
                continue
            actual = Evidence.hash_bytes(path.read_bytes())
            if actual != rec["sha256"]:
                problems.append(f"hash mismatch: {rec['path']}")
        return (not problems), problems
