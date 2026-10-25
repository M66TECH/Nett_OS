# SPDX-License-Identifier: AGPL-3.0-or-later
"""Règles de nettoyage propres à Windows.

Principes identiques au Linux : risque faible ou modéré, périmètre limité au
profil de l'utilisateur courant, aucune règle ne touche ``C:\\Windows``,
``WinSxS``, le registre, les pilotes ou les données applicatives persistantes.

Le dossier temporaire est la seule racine « système » utilisée, et il est
toujours examiné via ``%TEMP%`` **de l'utilisateur**, jamais via
``C:\\Windows\\Temp`` qui appartient au système.
"""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

from nettos.cleaners.declarative import DeclarativeCleaner
from nettos.cleaners.rules import CleanerRule, CleanTarget, Platform, RiskLevel

_REVIEWED = dt.date(2026, 10, 25)


class _WindowsUserCleaner(DeclarativeCleaner):
    """Base des nettoyeurs dont les racines vivent dans le profil utilisateur."""

    def __init__(self, profile: Path | None = None, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._profile = Path(profile) if profile is not None else _default_profile()

    def roots(self) -> list[Path]:
        """Racines sous le profil de l'utilisateur."""
        return [self._profile / path for path in self._relative_roots()]

    def _relative_roots(self) -> tuple[str, ...]:
        raise NotImplementedError


class WindowsTempCleaner(_WindowsUserCleaner):
    """Fichiers temporaires du profil utilisateur.

    Risque faible : un fichier temporaire encore utilisé est verrouillé par
    le système et la simulation le signale comme non supprimable plutôt que
    d'échouer.
    """

    RULE = CleanerRule(
        identifier="windows.user.temp",
        title="Fichiers temporaires de l'utilisateur",
        description=(
            "Contenu de %TEMP% plus ancien que sept jours. Les fichiers en cours "
            "d'utilisation sont verrouillés et ne sont pas proposés."
        ),
        version="1",
        platforms=frozenset({Platform.WINDOWS}),
        risk=RiskLevel.LOW,
        targets=(CleanTarget(pattern="**/*", description="Contenu de %TEMP%", max_age_days=7),),
        excluded=(
            # Fichiers temporaires de l'installateur en cours d'exécution.
            "**/*.tmp.lock",
            "**/MpCmdRun.log",
        ),
        valid_from=dt.date(2026, 1, 1),
        reviewed_on=_REVIEWED,
        reconstructed_cost="immédiat",
    )

    def _relative_roots(self) -> tuple[str, ...]:
        return ("AppData/Local/Temp",)


class WindowsThumbnailCacheCleaner(_WindowsUserCleaner):
    """Caches de miniatures de l'Explorateur.

    Risque faible : l'Explorateur régénère les miniatures à la demande.
    Les fichiers ``thumbcache_*.db`` sont des bases locales, sans données
    utilisateur uniques.
    """

    RULE = CleanerRule(
        identifier="windows.user.thumbnails",
        title="Caches de miniatures de l'Explorateur",
        description=(
            "Bases de miniatures de l'Explorateur Windows. Régénérées "
            "automatiquement à la prochaine ouverture d'un dossier."
        ),
        version="1",
        platforms=frozenset({Platform.WINDOWS}),
        risk=RiskLevel.LOW,
        targets=(
            CleanTarget(pattern="thumbcache_*.db", description="Cache de miniatures standard"),
            CleanTarget(
                pattern="thumbcache_*.db.*",
                description="Cache de miniatures secondaires",
            ),
            CleanTarget(
                pattern="wide_thumbcache_*.db",
                description="Cache de miniatures au format large",
            ),
        ),
        excluded=(
            # Bases de données applicatives : jamais des miniatures.
            "**/Microsoft/Office/**",
            "**/Packages/**",
        ),
        valid_from=dt.date(2026, 1, 1),
        reviewed_on=_REVIEWED,
        reconstructed_cost="immédiat (à l'ouverture du dossier)",
    )

    def _relative_roots(self) -> tuple[str, ...]:
        return ("AppData/Local/Microsoft/Windows/Explorer",)


class WindowsCrashDumpCleaner(_WindowsUserCleaner):
    """Rapports d'erreur Windows destinés à l'utilisateur.

    Risque modéré : ces fichiers ont une valeur de diagnostic. Ils ne sont
    proposés qu'après une période longue (30 jours).
    """

    RULE = CleanerRule(
        identifier="windows.user.crashdumps",
        title="Rapports d'erreur et vidages de l'utilisateur",
        description=(
            "Vidages mémoire et rapports d'erreur générés pour l'utilisateur. "
            "Utiles au diagnostic : proposés seulement après 30 jours."
        ),
        version="1",
        platforms=frozenset({Platform.WINDOWS}),
        risk=RiskLevel.MODERATE,
        targets=(
            CleanTarget(pattern="*.dmp", description="Vidages mémoire", max_age_days=30),
            CleanTarget(pattern="*.wer", description="Rapports d'erreur", max_age_days=30),
            CleanTarget(pattern="**/*.dmp", description="Vidages en sous-dossier", max_age_days=30),
        ),
        valid_from=dt.date(2026, 1, 1),
        reviewed_on=_REVIEWED,
        reconstructed_cost="impossible (perte de l'historique de diagnostic)",
    )

    def _relative_roots(self) -> tuple[str, ...]:
        return ("AppData/Local/CrashDumps", "AppData/Local/Microsoft/Windows/WER")


WINDOWS_CLEANERS: tuple[type[DeclarativeCleaner], ...] = (
    WindowsTempCleaner,
    WindowsThumbnailCacheCleaner,
    WindowsCrashDumpCleaner,
)
"""Liste explicite : seuls ces modules sont instanciables (règle 6)."""


def _default_profile() -> Path:
    """Profil utilisateur Windows (``%USERPROFILE%``)."""
    profile = os.environ.get("USERPROFILE")
    if profile:
        return Path(profile)
    return Path.home()
