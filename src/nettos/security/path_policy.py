# SPDX-License-Identifier: AGPL-3.0-or-later
"""Contrôles de chemin réutilisables.

Ces fonctions servent de brique commune au scanner et au futur moteur de
nettoyage. Elles n'effectuent aucune opération destructive et sont
testables indépendamment de l'interface.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from nettos.core.errors import PathOutsideAuthorizedRootError


def _normalize(path: Path) -> str:
    """Retourne une représentation comparable du chemin.

    Sur Windows, la comparaison est insensible à la casse et
    ``normcase`` normalise aussi les séparateurs. Sur POSIX, elle reste
    sensible à la casse.
    """
    text = os.path.normpath(str(path))
    if sys.platform.startswith("win"):
        return os.path.normcase(text)
    return text


def is_within_root(candidate: Path, root: Path) -> bool:
    """Indique si ``candidate`` est le même chemin que ``root`` ou en dessous.

    Comparaison lexicale après normalisation : aucun accès au disque n'est
    effectué. La vérification finale devra être réitérée au moment de
    l'opération (protection contre les courses critiques, section 5.3).
    """
    candidate_norm = _normalize(Path(candidate))
    root_norm = _normalize(Path(root))
    if candidate_norm == root_norm:
        return True
    return candidate_norm.startswith(root_norm.rstrip(os.sep) + os.sep)


def resolve_no_symlinks(path: Path, *, root: Path) -> Path:
    """Résout ``path`` et vérifie qu'il reste sous ``root``.

    Les liens symboliques rencontrés dans le chemin sont résolus, ainsi que
    la racine elle-même : sans cela, une racine exprimée avec un chemin
    court Windows (``MILKA-~1``) serait comparée à un candidat en chemin
    long, et **toute** cible serait jugée hors périmètre. Lève
    :class:`PathOutsideAuthorizedRootError` dès qu'une sortie est détectée.
    """
    resolved = Path(os.path.realpath(path))
    resolved_root = Path(os.path.realpath(root))
    if not is_within_root(resolved, resolved_root):
        raise PathOutsideAuthorizedRootError(
            f"Le chemin résolu {resolved!s} sort du périmètre autorisé {root!s}."
        )
    return resolved
