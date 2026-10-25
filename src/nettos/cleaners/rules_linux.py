# SPDX-License-Identifier: AGPL-3.0-or-later
"""Règles de nettoyage propres à Linux.

Toutes les règles sont en **risque faible** ou **modéré** et ne visent que
des caches reconstructibles de l'utilisateur courant. Aucune règle ne touche
``/etc``, ``/var/lib``, les journaux système ni un répertoire exigeant des
droits administrateur : ces cibles relèvent d'une décision documentée et
d'une autorisation dédiée (section 5.1, privilèges minimaux).
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from nettos.cleaners.declarative import DeclarativeCleaner
from nettos.cleaners.rules import CleanerRule, CleanTarget, Platform, RiskLevel

_REVIEWED = dt.date(2026, 10, 25)


class _UserHomeCleaner(DeclarativeCleaner):
    """Base des nettoyeurs dont les racines vivent dans le foyer utilisateur."""

    def __init__(self, home: Path | None = None, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._home = Path(home) if home is not None else Path.home()

    def roots(self) -> list[Path]:
        """Racines sous le foyer de l'utilisateur."""
        return [self._home / path for path in self._relative_roots()]

    def _relative_roots(self) -> tuple[str, ...]:
        raise NotImplementedError


class UserCacheCleaner(_UserHomeCleaner):
    """Caches applicatifs sous ``~/.cache`` (XDG).

    Les caches sont reconstructibles par les applications ; le coût de
    reconstruction varie de immédiat (miniatures) à long (caches de
    compilation).
    """

    RULE = CleanerRule(
        identifier="linux.user.cache",
        title="Caches applicatifs de l'utilisateur",
        description=(
            "Fichiers de cache reconstruits automatiquement par les applications "
            "sous ~/.cache. Leur suppression ne détruit aucune donnée utilisateur."
        ),
        version="1",
        platforms=frozenset({Platform.LINUX}),
        risk=RiskLevel.MODERATE,
        targets=(CleanTarget(pattern="**/*", description="Contenu de ~/.cache", max_age_days=7),),
        excluded=(
            # Un cache de compilation peut représenter des heures de calcul :
            # il n'est jamais supprimé par défaut.
            "**/ccache/**",
            "**/sccache/**",
            # Caches de gestionnaires de paquets : couverts par des règles dédiées.
            "**/pip/**",
            "**/npm/**",
            "**/yarn/**",
            "**/pnpm/**",
            # Sessions et secrets applicatifs mis en cache.
            "**/keyring/**",
            "**/gnupg/**",
            # Cache de polices : reconstruction coûteuse et sans gain réel.
            "**/fontconfig/**",
            # Caches de compilation de navigateurs et d'outils de build.
            "**/go-build/**",
            "**/meson/**",
        ),
        valid_from=dt.date(2026, 1, 1),
        reviewed_on=_REVIEWED,
        reconstructed_cost="variable selon l'application",
    )

    def _relative_roots(self) -> tuple[str, ...]:
        return (".cache",)


class ThumbnailCacheCleaner(_UserHomeCleaner):
    """Cache de miniatures (GNOME, KDE, Xfce).

    Risque faible : les miniatures sont régénérées à la première
    consultation du dossier.
    """

    RULE = CleanerRule(
        identifier="linux.user.thumbnails",
        title="Cache de miniatures du bureau",
        description=(
            "Miniatures d'images et de vidéos générées par le gestionnaire de "
            "fichiers. Régénérées automatiquement, sans perte de données."
        ),
        version="1",
        platforms=frozenset({Platform.LINUX}),
        risk=RiskLevel.LOW,
        targets=(
            CleanTarget(pattern="**/*.png", description="Miniatures PNG"),
            CleanTarget(pattern="**/*.jpg", description="Miniatures JPEG"),
            CleanTarget(pattern="**/*.jpeg", description="Miniatures JPEG"),
            CleanTarget(pattern="**/*.webp", description="Miniatures WebP"),
        ),
        valid_from=dt.date(2026, 1, 1),
        reviewed_on=_REVIEWED,
        reconstructed_cost="immédiat (à l'ouverture du dossier)",
    )

    def _relative_roots(self) -> tuple[str, ...]:
        return (".cache/thumbnails",)


class UserTrashCleaner(_UserHomeCleaner):
    """Corbeille de l'utilisateur (``~/.local/share/Trash``).

    Risque **modéré** et non faible : vider la corbeille détruit
    définitivement des fichiers que l'utilisateur avait intentionnellement
    conservés. Le moteur exigera une confirmation explicite (phase 4).
    """

    RULE = CleanerRule(
        identifier="linux.user.trash",
        title="Corbeille de l'utilisateur",
        description=(
            "Fichiers placés dans la corbeille. Leur suppression est définitive : "
            "aucune règle ne doit la déclencher sans décision explicite."
        ),
        version="1",
        platforms=frozenset({Platform.LINUX}),
        risk=RiskLevel.MODERATE,
        targets=(
            CleanTarget(pattern="files/**/*", description="Fichiers mis à la corbeille"),
            CleanTarget(pattern="info/*.trashinfo", description="Métadonnées associées"),
        ),
        excluded=("**/expunged/**",),
        valid_from=dt.date(2026, 1, 1),
        reviewed_on=_REVIEWED,
        reconstructed_cost="impossible (suppression définitive)",
    )

    def _relative_roots(self) -> tuple[str, ...]:
        return (".local/share/Trash",)


LINUX_CLEANERS: tuple[type[DeclarativeCleaner], ...] = (
    UserCacheCleaner,
    ThumbnailCacheCleaner,
    UserTrashCleaner,
)
"""Liste explicite : seuls ces modules sont instanciables (règle 6)."""
