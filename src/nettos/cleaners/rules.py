# SPDX-License-Identifier: AGPL-3.0-or-later
"""Modèle déclaratif d'une règle de nettoyage.

Une règle **décrit** ce qu'elle vise ; elle ne contient jamais de commande
arbitraire ni de code exécutable (cahier des charges, section 4.2, règle 3).
Le moteur lit cette description, la valide, puis décide — c'est ce qui rend
une règle auditable par un simple relecteur.

Chaque règle porte une version et une date de validité : un emplacement de
cache change avec les versions des outils, et une règle sans date devient
silencieusement fausse (section 6.4).
"""

from __future__ import annotations

import datetime as dt
import enum
from dataclasses import dataclass, field


class RiskLevel(enum.IntEnum):
    """Niveau de risque d'une opération, conditionnant l'affichage et les garde-fous.

    Ordonné : la comparaison ``rule.risk >= RiskLevel.HIGH`` est utile pour
    filtrer les opérations qui exigent une confirmation renforcée.
    """

    LOW = 1
    """Fichiers temporaires explicitement identifiés et non utilisés."""

    MODERATE = 2
    """Caches applicatifs connus, reconstructibles mais parfois coûteux."""

    HIGH = 3
    """Journaux utiles au diagnostic, caches partagés, données de paquets."""

    FORBIDDEN = 4
    """Interdit par défaut : documents, données persistantes, fichiers système."""

    @property
    def label(self) -> str:
        """Libellé stable pour l'affichage et le JSON."""
        return self.name.lower()

    @property
    def requires_extra_confirmation(self) -> bool:
        """``True`` si le niveau exige une confirmation renforcée."""
        return self >= RiskLevel.HIGH

    @classmethod
    def parse(cls, value: str) -> RiskLevel:
        """Analyse un libellé (insensible à la casse), avec erreur claire."""
        normalized = value.strip().lower()
        for member in cls:
            if member.label == normalized:
                return member
        allowed = ", ".join(member.label for member in cls)
        raise ValueError(f"Niveau de risque inconnu : {value!r} (attendu : {allowed})")


class Platform(enum.Enum):
    """Système d'exploitation sur lequel une règle est applicable."""

    LINUX = "linux"
    WINDOWS = "windows"

    @classmethod
    def parse(cls, value: str) -> Platform:
        """Analyse un nom de plateforme, avec erreur claire."""
        normalized = value.strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        allowed = ", ".join(member.value for member in cls)
        raise ValueError(f"Plateforme inconnue : {value!r} (attendu : {allowed})")


@dataclass(frozen=True, slots=True)
class CleanTarget:
    """Emplacement visé par une règle.

    ``pattern`` est relatif à la racine du répertoire fourni par la règle :
    il ne peut pas être absolu, ce qui empêche une règle d'atteindre un
    chemin arbitraire hors de sa racine (section 5.1, liste d'autorisation).
    """

    pattern: str
    description: str
    max_age_days: int | None = None
    """Ne cibler que les entrées plus anciennes que ce nombre de jours."""

    def __post_init__(self) -> None:
        if not self.pattern:
            raise ValueError("Le motif d'une cible ne peut pas être vide.")
        if self.pattern.startswith(("/", "\\")) or _looks_absolute(self.pattern):
            raise ValueError(
                f"Le motif {self.pattern!r} doit être relatif à la racine de la règle."
            )
        if ".." in _split_pattern(self.pattern):
            raise ValueError(f"Le motif {self.pattern!r} ne peut pas remonter hors de la racine.")
        if self.max_age_days is not None and self.max_age_days < 0:
            raise ValueError("max_age_days ne peut pas être négatif.")


@dataclass(frozen=True, slots=True)
class CleanerRule:
    """Description complète et déclarative d'une règle de nettoyage."""

    identifier: str
    """Identifiant stable, en minuscules avec points (``linux.system.temp``)."""

    title: str
    description: str
    version: str
    """Version de la règle (sémantique simplifiée : ``1``, ``1.2``…)."""

    platforms: frozenset[Platform]
    risk: RiskLevel
    targets: tuple[CleanTarget, ...]
    excluded: tuple[str, ...] = field(default_factory=tuple)
    """Motifs de chemins **toujours** exclus, vérifiés avant toute cible."""

    valid_from: dt.date | None = None
    reviewed_on: dt.date | None = None
    requires_admin: bool = False
    reconstructed_cost: str | None = None
    """Coût de reconstruction du cache, en clair (« immédiat », « long »…)."""

    def applies_to(self, platform: Platform) -> bool:
        """Indique si la règle s'applique à ``platform``."""
        return platform in self.platforms

    def __post_init__(self) -> None:
        if not self.identifier:
            raise ValueError("Une règle doit avoir un identifiant.")
        if not _is_valid_identifier(self.identifier):
            raise ValueError(
                f"Identifiant de règle invalide : {self.identifier!r} "
                "(attendu : minuscules, chiffres et points, séparés en segments)."
            )
        if not self.targets:
            raise ValueError(f"La règle {self.identifier} doit avoir au moins une cible.")
        if not self.platforms:
            raise ValueError(f"La règle {self.identifier} doit viser au moins une plateforme.")
        if self.risk is RiskLevel.FORBIDDEN:
            raise ValueError(
                f"La règle {self.identifier} est marquée FORBIDDEN : "
                "un niveau interdit ne peut pas être livré comme règle active."
            )
        if self.reviewed_on and self.valid_from and self.reviewed_on < self.valid_from:
            raise ValueError(
                f"La règle {self.identifier} a une date de revue antérieure à sa validité."
            )
        if self.valid_from and self.valid_from > dt.date.today():
            raise ValueError(
                f"La règle {self.identifier} n'est pas encore valide "
                f"(valid_from = {self.valid_from})."
            )

    @property
    def valid_for_days(self) -> int | None:
        """Ancienneté de la règle en jours (``None`` si non datée)."""
        if self.valid_from is None:
            return None
        return (dt.date.today() - self.valid_from).days

    @property
    def is_stale(self) -> bool:
        """``True`` si la règle n'a pas été revue depuis plus de 730 jours."""
        days = self.valid_for_days
        return days is not None and days > 730


def _split_pattern(pattern: str) -> list[str]:
    """Découpe un motif sur les deux séparateurs possibles."""
    return pattern.replace("\\", "/").split("/")


def _looks_absolute(pattern: str) -> bool:
    """Détecte un lecteur Windows ou un chemin absolu déguisé."""
    head = pattern.replace("\\", "/").split("/")[0]
    return len(head) == 2 and head[1] == ":"


def _is_valid_identifier(identifier: str) -> bool:
    """Valide ``domaine.sous-domaine.nom`` en minuscules ASCII."""
    if not identifier or identifier != identifier.lower():
        return False
    segments = identifier.split(".")
    if any(not segment for segment in segments):
        return False
    return all(
        segment[0].isalpha() and all(char.isalnum() or char in "-_" for char in segment)
        for segment in segments
    )
