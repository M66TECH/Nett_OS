# SPDX-License-Identifier: AGPL-3.0-or-later
"""Service d'analyse de stockage.

Expose le scanner aux interfaces (Qt et ligne de commande) sans
dupliquer de logique. Le service est volontairement mince en phase 1.
"""

from __future__ import annotations

from pathlib import Path

from nettos.core.result import ScanResult
from nettos.diagnostics.scanner import ProgressCallback, StorageScanner


class ScanService:
    """Orchestre un scan de stockage en lecture seule."""

    def __init__(self, progress: ProgressCallback | None = None) -> None:
        self._scanner = StorageScanner(progress=progress)

    def scan(self, root: Path) -> ScanResult:
        """Analyse ``root`` et retourne le résultat agrégé."""
        return self._scanner.scan(root)

    def as_dict(self, result: ScanResult) -> dict[str, object]:
        """Sérialise un résultat en dictionnaire pour ``--json``.

        Le format deviendra public en phase 2 ; il est isolé ici pour que
        la ligne de commande n'ait pas à connaître la structure interne.
        """
        return {
            "status": result.status.value,
            "total_files": result.total_files,
            "total_bytes": result.total_bytes,
            "error_count": result.error_count,
            "errors": [{"path": e.path, "reason": e.reason} for e in result.errors],
            "volumes": [
                {
                    "mount_point": v.mount_point,
                    "total_bytes": v.total_bytes,
                    "used_bytes": v.used_bytes,
                    "free_bytes": v.free_bytes,
                    "filesystem": v.filesystem,
                }
                for v in result.volumes
            ],
            "duration_seconds": round(result.duration_seconds, 3),
        }


__all__ = ["ProgressCallback", "ScanService"]
