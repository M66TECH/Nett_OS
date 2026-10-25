# SPDX-License-Identifier: AGPL-3.0-or-later
"""Contrat commun d'un nettoyeur (cahier des charges, section 6.2).

Un nettoyeur est **prévisible et testable** : il expose son identifiant, sa
version, ses plateformes, ses cibles, ses exclusions, son niveau de risque, sa
méthode de simulation, sa méthode d'exécution et sa façon de vérifier le
résultat.

En phase 3, aucun nettoyeur n'exécute de suppression : seule la
**simulation** est disponible, et :meth:`BaseCleaner.execute` est encore
impossible à appeler. C'est volontaire : la suppression arrive en phase 4,
derrière simulation, confirmation et quarantaine.
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from nettos.cleaners.rules import CleanerRule, RiskLevel
from nettos.core.result import ErrorKind


class CleanerStatus(enum.Enum):
    """État d'un nettoyeur dans le registre."""

    ACTIVE = "active"
    """Règle applicable et simulable."""

    NOT_APPLICABLE = "not_applicable"
    """Règle valide mais propre à une autre plateforme."""

    STALE = "stale"
    """Règle non revue depuis trop longtemps : affichée, jamais exécutée."""

    DISABLED = "disabled"
    """Règle désactivée nommément, avec une note dans le journal des modifications."""

    @property
    def is_executable(self) -> bool:
        """Seul un nettoyeur actif pourra être exécuté (phase 4)."""
        return self is CleanerStatus.ACTIVE


@dataclass(frozen=True, slots=True)
class CandidateFile:
    """Fichier proposé au nettoyage par une simulation."""

    path: str
    size_bytes: int
    modified_at: float
    age_days: float


@dataclass(frozen=True, slots=True)
class RejectedFile:
    """Chemin examiné puis écarté, avec la raison exacte du rejet.

    Rien n'est écarté sans explication : le rapport doit rester explicable
    (cahier des charges, section 7.5).
    """

    path: str
    reason: str
    kind: ErrorKind = ErrorKind.OTHER


@dataclass(slots=True)
class SimulationResult:
    """Résultat d'une simulation, strictement sans effet de bord."""

    rule_identifier: str
    candidates: list[CandidateFile] = field(default_factory=list)
    rejected: list[RejectedFile] = field(default_factory=list)
    missing_roots: list[str] = field(default_factory=list)
    truncated: bool = False
    """``True`` si la limite de sécurité a coupé l'énumération."""

    @property
    def total_bytes(self) -> int:
        """Espace théoriquement récupérable (voir la nuance en phase 4)."""
        return sum(candidate.size_bytes for candidate in self.candidates)

    @property
    def file_count(self) -> int:
        """Nombre de fichiers proposés."""
        return len(self.candidates)

    @property
    def rejected_count(self) -> int:
        """Nombre de chemins écartés, toutes raisons confondues."""
        return len(self.rejected)


class BaseCleaner(ABC):
    """Classe de base de tous les nettoyeurs.

    Un nettoyeur ne décide pas seul de son droit à supprimer : il décrit sa
    règle, simule, et le moteur applique la politique. Cette séparation est
    ce qui rend la règle n°1 (« l'interface ne supprime jamais directement »)
    vérifiable par inspection.
    """

    #: Nombre maximal de fichiers collectés par une simulation.
    MAX_CANDIDATES = 100_000

    @property
    @abstractmethod
    def rule(self) -> CleanerRule:
        """Description déclarative de la règle."""

    @property
    def identifier(self) -> str:
        """Raccourci vers l'identifiant de la règle."""
        return self.rule.identifier

    @property
    def risk(self) -> RiskLevel:
        """Raccourci vers le niveau de risque."""
        return self.rule.risk

    @abstractmethod
    def roots(self) -> list[Path]:
        """Racines autorisées, résolues pour la plateforme courante.

        Une règle ne peut viser que des chemins **sous** ces racines. Les
        racines inexistantes sont signalées, jamais créées.
        """

    @abstractmethod
    def simulate(self) -> SimulationResult:
        """Énumère les cibles sans rien modifier.

        Garantie : la simulation ne supprime ni ne modifie aucun fichier.
        Elle est testée explicitement en étage de sécurité.
        """

    def describe(self) -> dict[str, object]:
        """Représentation stable pour l'affichage et le JSON."""
        rule = self.rule
        return {
            "identifier": rule.identifier,
            "title": rule.title,
            "description": rule.description,
            "version": rule.version,
            "risk": rule.risk.label,
            "platforms": sorted(platform.value for platform in rule.platforms),
            "targets": [
                {
                    "pattern": target.pattern,
                    "description": target.description,
                    "max_age_days": target.max_age_days,
                }
                for target in rule.targets
            ],
            "excluded": list(rule.excluded),
            "requires_admin": rule.requires_admin,
            "reconstructed_cost": rule.reconstructed_cost,
            "valid_from": rule.valid_from.isoformat() if rule.valid_from else None,
            "reviewed_on": rule.reviewed_on.isoformat() if rule.reviewed_on else None,
            "is_stale": rule.is_stale,
        }

    def execute(self, *args: object, **kwargs: object) -> None:
        """Exécution réelle : **non disponible avant la phase 4**.

        Une méthode qui lève est préférable à une méthode qui devine : elle
        rend impossible par construction toute suppression accidentelle
        depuis un chemin de code qui n'a pas intégré le pipeline complet.
        """
        raise NotImplementedError(
            "L'exécution de nettoyage n'est pas disponible : elle sera livrée en "
            "phase 4 avec simulation, confirmation explicite et quarantaine."
        )


__all__ = [
    "BaseCleaner",
    "CandidateFile",
    "CleanerStatus",
    "RejectedFile",
    "SimulationResult",
]
