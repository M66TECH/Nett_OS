# SPDX-License-Identifier: AGPL-3.0-or-later
"""Scanner de stockage en lecture seule.

C'est le premier livrable fonctionnel du projet (cahier des charges,
section 13). La phase 1 fournit le contrat et un parcours de répertoires
naïf mais correct ; les optimisations (ne pas suivre les liens, flux
d'agrégats, annulation) seront ajoutées et testées en phase 2.

Aucune opération d'écriture n'est effectuée ici.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path

from nettos.core.result import ScanErrorRecord, ScanResult

ProgressCallback = Callable[[int, int], None]


class StorageScanner:
    """Parcourt une arborescence et agrège tailles et erreurs.

    Le scanner ne suit jamais les liens symboliques : un lien est compté
    comme une entrée mais son contenu n'est pas parcouru, ce qui évite de
    sortir de l'arborescence autorisée par inadvertance.
    """

    def __init__(self, progress: ProgressCallback | None = None) -> None:
        self._progress = progress

    def scan(self, root: Path) -> ScanResult:
        """Analyse ``root`` en lecture seule et retourne un résultat agrégé."""
        started = time.perf_counter()
        result = ScanResult()
        root = Path(root)

        if not root.exists():
            result.errors.append(ScanErrorRecord(path=str(root), reason="chemin inexistant"))
            result.mark_partial()
            result.duration_seconds = time.perf_counter() - started
            return result

        stack: list[Path] = [root]
        visited_entries = 0

        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        visited_entries += 1
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(Path(entry.path))
                            elif entry.is_file(follow_symlinks=False):
                                try:
                                    size = entry.stat(follow_symlinks=False).st_size
                                except OSError as exc:
                                    result.errors.append(
                                        ScanErrorRecord(path=entry.path, reason=str(exc))
                                    )
                                    result.mark_partial()
                                    continue
                                result.total_files += 1
                                result.total_bytes += size
                        except OSError as exc:
                            result.errors.append(ScanErrorRecord(path=entry.path, reason=str(exc)))
                            result.mark_partial()
                        if self._progress is not None:
                            self._progress(visited_entries, result.total_bytes)
            except PermissionError as exc:
                result.errors.append(ScanErrorRecord(path=str(current), reason=str(exc)))
                result.mark_partial()
            except OSError as exc:
                result.errors.append(ScanErrorRecord(path=str(current), reason=str(exc)))
                result.mark_partial()

        result.duration_seconds = time.perf_counter() - started
        return result
