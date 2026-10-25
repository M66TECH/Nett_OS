# SPDX-License-Identifier: AGPL-3.0-or-later
"""Modèles de résultats du diagnostic.

Ces structures sont le contrat entre le moteur (sans Qt) et les couches
supérieures (services, interface, ligne de commande).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DiagnosticStatus(str, Enum):
    """Statut d'un diagnostic.

    ``UNKNOWN`` est une réponse légitime et attendue : NettOS préfère
    déclarer qu'il ne sait pas plutôt que d'inventer une cause
    (cahier des charges, section 7.5).
    """

    OK = "ok"
    PARTIAL = "partial"
    UNKNOWN = "unknown"
    CANCELLED = "cancelled"


class ErrorKind(str, Enum):
    """Catégorie d'une erreur de parcours, pour agrégation et affichage."""

    PERMISSION_DENIED = "permission_denied"
    NOT_FOUND = "not_found"
    IO_ERROR = "io_error"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class ScanErrorRecord:
    """Erreur rencontrée pendant un scan, conservée pour le rapport."""

    path: str
    reason: str
    kind: ErrorKind = ErrorKind.OTHER


@dataclass(frozen=True, slots=True)
class VolumeInfo:
    """Informations sur un volume monté."""

    mount_point: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    filesystem: str | None = None

    @property
    def used_ratio(self) -> float:
        """Proportion utilisée, entre 0 et 1 (0 si volume vide)."""
        if self.total_bytes <= 0:
            return 0.0
        return min(self.used_bytes / self.total_bytes, 1.0)


@dataclass(frozen=True, slots=True)
class DirectorySize:
    """Taille agrégée d'un répertoire, indexée par chemin relatif."""

    path: str
    size_bytes: int
    file_count: int


@dataclass(slots=True)
class ScanResult:
    """Résultat agrégé d'une analyse en lecture seule.

    Le résultat est construit en flux : ``total_files`` et ``total_bytes``
    sont incrémentés au fil du parcours, sans conserver la liste des
    fichiers en mémoire (budget mémoire de la section 8.1).
    """

    volumes: list[VolumeInfo] = field(default_factory=list)
    total_files: int = 0
    total_bytes: int = 0
    allocated_bytes: int = 0
    total_entries: int = 0
    errors: list[ScanErrorRecord] = field(default_factory=list)
    directories: list[DirectorySize] = field(default_factory=list)
    status: DiagnosticStatus = DiagnosticStatus.OK
    duration_seconds: float = 0.0
    root: str = ""

    @property
    def error_count(self) -> int:
        """Nombre d'erreurs rencontrées pendant le scan."""
        return len(self.errors)

    @property
    def error_count_by_kind(self) -> dict[str, int]:
        """Nombre d'erreurs par catégorie, pour les rapports agrégés."""
        counts: dict[str, int] = {}
        for record in self.errors:
            counts[record.kind.value] = counts.get(record.kind.value, 0) + 1
        return counts

    def mark_partial(self) -> None:
        """Le scan est incomplet : des zones n'ont pas pu être lues."""
        if self.status is DiagnosticStatus.OK:
            self.status = DiagnosticStatus.PARTIAL
