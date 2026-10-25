# SPDX-License-Identifier: AGPL-3.0-or-later
"""Registre explicite des nettoyeurs (cahier des charges, règle 6).

Aucun module n'est découvert automatiquement sur le disque : le registre
contient une **liste littérale** de classes. C'est la seule barrière qui
empêche l'exécution de code non revu si un fichier est déposé dans un
répertoire utilisateur.

Le registre ne fournit jamais l'instance : il l'instancie lui-même, ce qui
permet de garantir qu'un nettoyeur refusé (obsolète, désactivé, ou destiné à
une autre plateforme) n'est **jamais** construit.
"""

from __future__ import annotations

import datetime as dt
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from nettos.cleaners.base import BaseCleaner, CleanerStatus
from nettos.cleaners.rules import CleanerRule, Platform, RiskLevel
from nettos.cleaners.rules_linux import LINUX_CLEANERS
from nettos.cleaners.rules_windows import WINDOWS_CLEANERS

MAX_RULE_AGE_DAYS = 730
"""Au-delà, une règle est considérée obsolète et n'est plus exécutable."""


def current_platform() -> Platform:
    """Plateforme courante, exprimée avec le vocabulaire du domaine."""
    if sys.platform.startswith("win"):
        return Platform.WINDOWS
    return Platform.LINUX


@dataclass(frozen=True, slots=True)
class RegisteredCleaner:
    """Entrée du registre : une fabrique, son statut et la raison du statut."""

    cleaner_type: type[BaseCleaner]
    rule: CleanerRule | None
    status: CleanerStatus
    reason: str = ""
    extra: dict[str, object] = field(default_factory=dict)

    @property
    def identifier(self) -> str | None:
        """Identifiant de la règle, ``None`` si la règle est illisible."""
        return self.rule.identifier if self.rule is not None else None


class CleanerRegistry:
    """Liste blanche des nettoyeurs livrés avec l'application."""

    def __init__(
        self,
        platform: Platform | None = None,
        *,
        today: dt.date | None = None,
        disabled: frozenset[str] = frozenset(),
    ) -> None:
        self._platform = platform or current_platform()
        self._today = today or dt.date.today()
        self._disabled = disabled
        self._entries: list[RegisteredCleaner] = self._build_entries()

    @property
    def platform(self) -> Platform:
        """Plateforme pour laquelle le registre a été construit."""
        return self._platform

    def entries(self) -> list[RegisteredCleaner]:
        """Toutes les entrées connues, quel que soit leur statut."""
        return list(self._entries)

    def active_entries(self) -> list[RegisteredCleaner]:
        """Entrées exécutables sur la plateforme courante."""
        return [entry for entry in self._entries if entry.status is CleanerStatus.ACTIVE]

    def instantiate(self, identifier: str) -> BaseCleaner:
        """Instancie un nettoyeur **uniquement** s'il est actif.

        Lève :class:`KeyError` si l'identifiant est inconnu et
        :class:`PermissionError` s'il n'est pas actif : un nettoyeur obsolète,
        désactivé ou destiné à une autre plateforme est inconstructible.
        """
        for entry in self._entries:
            if entry.identifier != identifier:
                continue
            if entry.status is not CleanerStatus.ACTIVE:
                raise PermissionError(
                    f"Le nettoyeur {identifier!r} n'est pas actif "
                    f"({entry.status.value}) : {entry.reason}"
                )
            return entry.cleaner_type()
        raise KeyError(f"Nettoyeur inconnu : {identifier!r}")

    def get(self, identifier: str) -> CleanerRule | None:
        """Règle déclarative d'un nettoyeur, sans l'instancier."""
        for entry in self._entries:
            if entry.identifier == identifier:
                return entry.rule
        return None

    def simulate(self, identifier: str) -> object:
        """Simule un nettoyeur actif (délégué à l'instance)."""
        return self.instantiate(identifier).simulate()

    def __iter__(self) -> Iterator[RegisteredCleaner]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def _build_entries(self) -> list[RegisteredCleaner]:
        entries: list[RegisteredCleaner] = []
        for cleaner_type in _all_cleaner_types():
            rule = getattr(cleaner_type, "RULE", None)
            if not isinstance(rule, CleanerRule):
                entries.append(
                    RegisteredCleaner(
                        cleaner_type=cleaner_type,
                        rule=None,
                        status=CleanerStatus.DISABLED,
                        reason="règle illisible (déclaration incomplète)",
                    )
                )
                continue
            status, reason = self._evaluate(rule)
            entries.append(
                RegisteredCleaner(
                    cleaner_type=cleaner_type,
                    rule=rule,
                    status=status,
                    reason=reason,
                )
            )
        entries.sort(key=lambda entry: entry.identifier or "")
        return entries

    def _evaluate(self, rule: CleanerRule) -> tuple[CleanerStatus, str]:
        identifier = rule.identifier
        if identifier in self._disabled:
            return CleanerStatus.DISABLED, "désactivée nommément"
        if not rule.applies_to(self._platform):
            return CleanerStatus.NOT_APPLICABLE, f"propre à {_platform_label(rule)}"
        if rule.risk is RiskLevel.FORBIDDEN:
            return CleanerStatus.DISABLED, "niveau de risque interdit"
        if rule.reviewed_on is not None:
            age = (self._today - rule.reviewed_on).days
            if age > MAX_RULE_AGE_DAYS:
                return CleanerStatus.STALE, f"non revue depuis {age} jours"
        return CleanerStatus.ACTIVE, ""


def _all_cleaner_types() -> tuple[type[BaseCleaner], ...]:
    """Liste littérale, jamais découverte dynamiquement."""
    return (*LINUX_CLEANERS, *WINDOWS_CLEANERS)


def _platform_label(rule: CleanerRule) -> str:
    return "/".join(sorted(platform.value for platform in rule.platforms))


def default_registry(
    platform: Platform | None = None,
    *,
    disabled: frozenset[str] = frozenset(),
) -> CleanerRegistry:
    """Construit le registre livré avec l'application."""
    return CleanerRegistry(platform=platform, disabled=disabled)


def user_data_dirs(platform: Platform, home: Path | None = None) -> dict[str, Path]:
    """Répertoires de données typiques, pour documentation et diagnostics."""
    base = Path(home) if home is not None else Path.home()
    if platform is Platform.LINUX:
        return {"cache": base / ".cache", "data": base / ".local/share"}
    return {"cache": base / "AppData/Local", "data": base / "AppData/Roaming"}


__all__ = [
    "MAX_RULE_AGE_DAYS",
    "CleanerRegistry",
    "RegisteredCleaner",
    "current_platform",
    "default_registry",
    "user_data_dirs",
]
