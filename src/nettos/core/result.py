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


@dataclass(frozen=True, slots=True)
class ScanErrorRecord:
    """Erreur rencontrée pendant un scan, conservée pour le rapport."""

    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class VolumeInfo:
    """Informations sur un volume monté."""

    mount_point: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    filesystem: str | None = None


@dataclass(slots=True)
class ScanResult:
    """Résultat agrégé d'une analyse en lecture seule."""

    volumes: list[VolumeInfo] = field(default_factory=list)
    total_files: int = 0
    total_bytes: int = 0
    errors: list[ScanErrorRecord] = field(default_factory=list)
    status: DiagnosticStatus = DiagnosticStatus.OK
    duration_seconds: float = 0.0

    @property
    def error_count(self) -> int:
        """Nombre d'erreurs rencontrées pendant le scan."""
        return len(self.errors)

    def mark_partial(self) -> None:
        """Le scan est incomplet : des zones n'ont pas pu être lues."""
        if self.status is DiagnosticStatus.OK:
            self.status = DiagnosticStatus.PARTIAL
