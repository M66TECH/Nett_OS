# SPDX-License-Identifier: AGPL-3.0-or-later
"""Scanner de stockage en lecture seule.

C'est le premier livrable fonctionnel du projet (cahier des charges,
section 13). Objectifs de la phase 2 :

- parcours itératif avec pile explicite (pas de limite de récursion) ;
- **aucun point d'analyse suivi** (liens symboliques, junctions NTFS) ;
- agrégats en flux : ni la liste des fichiers ni leur contenu ne sont
  conservés en mémoire (budget de 300 Mo pour un million de fichiers) ;
- erreurs classées et comptées, jamais avalées (critère de blocage) ;
- annulation coopérative via :class:`CancellationToken` ;
- tailles logiques **et** allouées lorsque la plateforme les expose.

Aucune opération d'écriture n'est effectuée ici.
"""

from __future__ import annotations

import errno
import os
import stat
import time
from collections.abc import Callable
from pathlib import Path

from nettos.core.cancellation import CancellationToken
from nettos.core.errors import OperationCancelledError, ScanLimitExceededError
from nettos.core.result import (
    DiagnosticStatus,
    DirectorySize,
    ErrorKind,
    ScanErrorRecord,
    ScanResult,
)
from nettos.diagnostics.filesystem import is_link_like, is_regular_directory

ProgressCallback = Callable[[int, int], None]

MAX_DIRECTORIES = 4_000_000
"""Garde-fou contre les boucles de points d'analyse non détectées."""

_PROGRESS_EVERY_ENTRIES = 2048


def _error_kind(exc: OSError) -> ErrorKind:
    """Classe une erreur système en catégorie exploitable par les rapports."""
    if isinstance(exc, PermissionError):
        return ErrorKind.PERMISSION_DENIED
    if isinstance(exc, FileNotFoundError):
        return ErrorKind.NOT_FOUND
    if exc.errno in (errno.EACCES, errno.EPERM):
        return ErrorKind.PERMISSION_DENIED
    if exc.errno in (errno.ENOENT, errno.ENOTDIR):
        return ErrorKind.NOT_FOUND
    if exc.errno is not None:
        return ErrorKind.IO_ERROR
    return ErrorKind.OTHER


class StorageScanner:
    """Parcourt une arborescence et agrège taille, fichiers et erreurs.

    Le scanner ne suit jamais les liens symboliques ni les points
    d'analyse : une junction Windows est comptée comme une entrée mais
    n'est jamais parcourue, ce qui évite de sortir de l'arborescence
    autorisée et de compter deux fois les mêmes fichiers.
    """

    def __init__(
        self,
        progress: ProgressCallback | None = None,
        cancellation: CancellationToken | None = None,
    ) -> None:
        self._progress = progress
        self._cancellation = cancellation

    def scan(self, root: Path) -> ScanResult:
        """Analyse ``root`` en lecture seule et retourne un résultat agrégé."""
        started = time.perf_counter()
        result = ScanResult(root=str(root))
        root = Path(root)

        if not root.exists():
            result.errors.append(
                ScanErrorRecord(
                    path=str(root),
                    reason="chemin inexistant",
                    kind=ErrorKind.NOT_FOUND,
                )
            )
            result.mark_partial()
            result.duration_seconds = time.perf_counter() - started
            return result

        sizes: dict[str, int] = {}
        counts: dict[str, int] = {}

        stack: list[Path] = [root]
        seen_directories = 0

        try:
            while stack:
                if self._cancellation is not None:
                    self._cancellation.raise_if_cancelled()

                current = stack.pop()
                seen_directories += 1
                if seen_directories > MAX_DIRECTORIES:
                    raise ScanLimitExceededError(
                        f"Limite de {MAX_DIRECTORIES} répertoires atteinte : "
                        "structure probablement cyclique."
                    )

                directory_size = 0
                directory_files = 0

                try:
                    with os.scandir(current) as iterator:
                        for entry in iterator:
                            result.total_entries += 1
                            if self._cancellation is not None:
                                self._cancellation.raise_if_cancelled()

                            try:
                                if is_link_like(entry):
                                    continue
                                if is_regular_directory(entry):
                                    stack.append(Path(entry.path))
                                    continue
                                file_size, allocated = self._measure_file(entry, result)
                                if file_size is None:
                                    continue
                                directory_size += file_size
                                directory_files += 1
                                result.total_files += 1
                                result.total_bytes += file_size
                                result.allocated_bytes += allocated
                            except OSError as exc:
                                self._record_error(result, entry.path, exc)

                            if (
                                self._progress is not None
                                and result.total_entries % _PROGRESS_EVERY_ENTRIES == 0
                            ):
                                self._progress(result.total_files, result.total_bytes)
                except PermissionError as exc:
                    self._record_error(result, str(current), exc)
                except OSError as exc:
                    self._record_error(result, str(current), exc)

                sizes[str(current)] = directory_size
                counts[str(current)] = directory_files
                self._report_progress(result, force=False)
        except OperationCancelledError:
            result.status = DiagnosticStatus.CANCELLED
            result.duration_seconds = time.perf_counter() - started
            return result
        except ScanLimitExceededError as exc:
            result.errors.append(
                ScanErrorRecord(path=str(root), reason=str(exc), kind=ErrorKind.OTHER)
            )
            result.mark_partial()

        self._report_progress(result, force=True)
        self._aggregate_directories(result, root, sizes, counts)
        result.duration_seconds = time.perf_counter() - started
        return result

    def _measure_file(self, entry: os.DirEntry[str], result: ScanResult) -> tuple[int | None, int]:
        """Retourne ``(taille logique, taille allouée)`` d'un fichier ordinaire.

        La taille allouée reflète l'espace réellement consommé sur le disque
        (blocs) ; elle diffère de la taille logique pour les fichiers creux
        et compressés. Sous Windows, seule la taille logique est exposée par
        ``stat``, donc la taille allouée n'est pas renseignée.
        """
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError as exc:
            self._record_error(result, entry.path, exc)
            return None, 0
        if not stat.S_ISREG(info.st_mode):
            return None, 0
        blocks = getattr(info, "st_blocks", None)
        allocated = blocks * 512 if blocks is not None else info.st_size
        return info.st_size, allocated

    @staticmethod
    def _record_error(result: ScanResult, path: str, exc: OSError) -> None:
        """Consigne une erreur sans interrompre le parcours."""
        reason = str(exc) or exc.__class__.__name__
        result.errors.append(ScanErrorRecord(path=path, reason=reason, kind=_error_kind(exc)))
        result.mark_partial()

    def _report_progress(self, result: ScanResult, *, force: bool) -> None:
        if self._progress is None:
            return
        if force or result.total_entries % _PROGRESS_EVERY_ENTRIES == 0:
            self._progress(result.total_files, result.total_bytes)

    @staticmethod
    def _aggregate_directories(
        result: ScanResult,
        root: Path,
        sizes: dict[str, int],
        counts: dict[str, int],
    ) -> None:
        """Remonte les tailles enfants vers leurs parents (agrégat complet)."""
        root_key = str(root)
        for path in sorted(sizes, key=len, reverse=True):
            if path == root_key:
                continue
            parent = str(Path(path).parent)
            if parent in sizes:
                sizes[parent] += sizes[path]
                counts[parent] += counts[path]

        result.directories = [
            DirectorySize(path=path, size_bytes=size, file_count=counts.get(path, 0))
            for path, size in sizes.items()
        ]
