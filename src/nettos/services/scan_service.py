# SPDX-License-Identifier: AGPL-3.0-or-later
"""Service d'analyse de stockage.

Expose le scanner aux interfaces (Qt et ligne de commande) sans
dupliquer de logique. C'est le seul endroit qui sait comment un scan
combine les volumes de la plateforme et le parcours d'arborescence.
"""

from __future__ import annotations

from pathlib import Path

from nettos.adapters import get_platform_adapter
from nettos.core.cancellation import CancellationToken
from nettos.core.result import DirectorySize, ScanResult
from nettos.diagnostics.scanner import ProgressCallback, StorageScanner

TOP_DIRECTORIES_JSON = 200
"""Nombre de répertoires exportés par défaut en JSON (rapport lisible)."""


class ScanService:
    """Orchestre un scan de stockage en lecture seule."""

    def __init__(
        self,
        progress: ProgressCallback | None = None,
        cancellation: CancellationToken | None = None,
    ) -> None:
        self._scanner = StorageScanner(progress=progress, cancellation=cancellation)

    def scan(self, root: Path, *, include_volumes: bool = True) -> ScanResult:
        """Analyse ``root`` et complète le résultat avec les volumes montés.

        L'échec de l'énumération des volumes ne fait pas échouer le scan :
        il est signalé dans les erreurs du résultat (aucune erreur avalée).
        """
        result = self._scanner.scan(Path(root))

        if include_volumes:
            try:
                adapter = get_platform_adapter()
            except Exception:
                return result
            try:
                result.volumes = adapter.list_volumes()
            except OSError as exc:
                from nettos.core.result import ErrorKind, ScanErrorRecord

                result.errors.append(
                    ScanErrorRecord(
                        path=str(root),
                        reason=f"énumération des volumes impossible : {exc}",
                        kind=ErrorKind.IO_ERROR,
                    )
                )
                result.mark_partial()
        return result

    def as_dict(
        self,
        result: ScanResult,
        *,
        top_directories: int = TOP_DIRECTORIES_JSON,
    ) -> dict[str, object]:
        """Sérialise un résultat pour ``--json``.

        Le format est public : il est stable sur une série mineure et
        versionné par la clé ``schema``. Seuls les plus gros répertoires
        sont exportés afin de garder un rapport exploitable sur un volume
        entier (le détail complet vit dans SQLite à la phase 5).
        """
        ranked = sorted(result.directories, key=lambda d: d.size_bytes, reverse=True)
        return {
            "schema": "nettos.scan/1",
            "status": result.status.value,
            "root": result.root,
            "total_files": result.total_files,
            "total_bytes": result.total_bytes,
            "allocated_bytes": result.allocated_bytes,
            "total_entries": result.total_entries,
            "error_count": result.error_count,
            "error_count_by_kind": result.error_count_by_kind,
            "errors": [
                {"path": e.path, "reason": e.reason, "kind": e.kind.value} for e in result.errors
            ],
            "volumes": [_volume_to_dict(v) for v in result.volumes],
            "directories": [_directory_to_dict(d) for d in ranked[:top_directories]],
            "directories_truncated": len(ranked) > top_directories,
            "duration_seconds": round(result.duration_seconds, 3),
        }


def _volume_to_dict(volume: object) -> dict[str, object]:
    from nettos.core.result import VolumeInfo

    assert isinstance(volume, VolumeInfo)
    return {
        "mount_point": volume.mount_point,
        "total_bytes": volume.total_bytes,
        "used_bytes": volume.used_bytes,
        "free_bytes": volume.free_bytes,
        "used_ratio": round(volume.used_ratio, 4),
        "filesystem": volume.filesystem,
    }


def _directory_to_dict(entry: DirectorySize) -> dict[str, object]:
    return {
        "path": entry.path,
        "size_bytes": entry.size_bytes,
        "file_count": entry.file_count,
    }


__all__ = ["ProgressCallback", "ScanService"]
