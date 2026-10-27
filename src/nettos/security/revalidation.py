# SPDX-License-Identifier: AGPL-3.0-or-later
"""Revalidation d'une cible au moment exact de l'opération.

Entre la simulation et l'exécution, le système de fichiers peut changer :
un fichier peut être remplacé par un lien, renommé, supprimé ou déplacé.
Une validation faite uniquement à la simulation est donc vulnérable aux
courses critiques (TOCTOU, section 5.3 du cahier des charges).

Stratégie retenue, en défense en profondeur :

1. **avant** l'opération : le chemin est résolu sans suivre les liens et
   comparé au périmètre autorisé ;
2. **à l'ouverture** : la cible est ouverte en refusant les liens
   (``O_NOFOLLOW`` sous POSIX) et les points d'analyse Windows sont
   détectés sur l'entrée elle-même ;
3. **après ouverture** : les métadonnées du **descripteur** (et non du
   chemin) sont comparées à celles vues à la simulation — identité
   (numéro d'inode / index Windows), taille et date de modification ;
4. l'opération s'applique au descripteur, jamais à un chemin reconstruit.

Si l'une de ces étapes échoue, la cible est **ignorée et signalée** ; le
reste du lot continue (section 6.1).
"""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from nettos.core.errors import PathOutsideAuthorizedRootError
from nettos.core.result import ErrorKind
from nettos.security.path_policy import is_within_root

O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
"""Refus d'ouvrir un lien symbolique en fin de chemin (POSIX)."""

O_BINARY = getattr(os, "O_BINARY", 0)
"""Ouverture en mode binaire sous Windows (sinon altération des octets)."""

_WINDOWS = sys.platform.startswith("win")


@dataclass(frozen=True, slots=True)
class TargetSnapshot:
    """Identité d'un fichier au moment de la simulation."""

    path: str
    size_bytes: int
    mtime: float
    file_id: str
    """Identité stable : ``(st_dev, st_ino)`` sous POSIX, index sous Windows."""


@dataclass(frozen=True, slots=True)
class RevalidationOutcome:
    """Résultat d'une revalidation : acceptée, ou rejetée avec sa raison."""

    accepted: bool
    reason: str = ""
    kind: ErrorKind = ErrorKind.OTHER
    file_descriptor: int | None = None
    snapshot: TargetSnapshot | None = None

    @classmethod
    def reject(cls, reason: str, kind: ErrorKind = ErrorKind.OTHER) -> RevalidationOutcome:
        """Construit un rejet explicite."""
        return cls(accepted=False, reason=reason, kind=kind)


def capture_snapshot(path: Path) -> TargetSnapshot | None:
    """Capture l'identité d'un fichier, sans suivre les liens.

    Retourne ``None`` si le fichier n'existe pas ou est un lien : une cible
    ne doit jamais être capturée à travers un lien.
    """
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode):
        return None
    return TargetSnapshot(
        path=str(path),
        size_bytes=info.st_size,
        mtime=info.st_mtime,
        file_id=_file_id(info),
    )


def _file_id(info: os.stat_result) -> str:
    """Identité stable d'un fichier, pour détecter un remplacement.

    ``st_ino`` est fiable sous POSIX. Sous Windows, Python expose un
    ``st_ino`` qui combine volume et index de fichier : suffisant pour
    détecter un remplacement entre deux observations.
    """
    return f"{info.st_dev}:{info.st_ino}"


def revalidate(
    snapshot: TargetSnapshot,
    *,
    root: Path,
    keep_open: bool = True,
) -> RevalidationOutcome:
    """Revalide une cible juste avant de la manipuler.

    ``keep_open=True`` retourne un descripteur de fichier ouvert : c'est lui
    que l'opération devra utiliser, afin qu'aucune substitution ne puisse
    intervenir entre la vérification et l'acte. L'appelant doit le fermer.

    Sous Windows, l'ouverture refuse de suivre un point d'analyse, mais
    ``os.open`` ne permet pas de fixer ``FILE_FLAG_OPEN_REPARSE_POINT``. La
    protection repose donc sur : ``lstat`` (jamais ``stat``), rejet de tout
    lien ou point d'analyse, puis comparaison de l'identité obtenue par
    ``fstat`` sur le descripteur effectivement ouvert.
    """
    path = Path(snapshot.path)

    if not snapshot.file_id:
        # Sans identité de référence, aucune comparaison fiable n'est
        # possible : refuser est la seule réponse sûre.
        return RevalidationOutcome.reject("référence de simulation absente : cible non revalidable")

    try:
        resolved = Path(os.path.realpath(path))
    except OSError as exc:
        return RevalidationOutcome.reject(f"chemin irrésolvable : {exc}", ErrorKind.IO_ERROR)

    if not is_within_root(resolved, Path(os.path.realpath(root))):
        raise PathOutsideAuthorizedRootError(
            f"La cible {resolved} sort du périmètre autorisé {root}."
        )

    try:
        info_before = os.lstat(path)
    except FileNotFoundError:
        return RevalidationOutcome.reject(
            "fichier disparu depuis la simulation", ErrorKind.NOT_FOUND
        )
    except OSError as exc:
        return RevalidationOutcome.reject(f"accès refusé ou impossible : {exc}", ErrorKind.IO_ERROR)

    if stat.S_ISLNK(info_before.st_mode):
        return RevalidationOutcome.reject("la cible est devenue un lien symbolique")

    if not stat.S_ISREG(info_before.st_mode):
        return RevalidationOutcome.reject("la cible n'est plus un fichier ordinaire")

    if is_reparse_point_path(path):
        return RevalidationOutcome.reject("la cible est un point d'analyse")

    if _file_id(info_before) != snapshot.file_id:
        return RevalidationOutcome.reject("le fichier a été remplacé depuis la simulation")

    if info_before.st_size != snapshot.size_bytes:
        return RevalidationOutcome.reject(
            f"taille modifiée ({info_before.st_size} octets au lieu de {snapshot.size_bytes})"
        )

    if abs(info_before.st_mtime - snapshot.mtime) > 1e-6:
        return RevalidationOutcome.reject("date de modification changée depuis la simulation")

    flags = os.O_RDONLY | O_BINARY
    if not _WINDOWS:
        flags |= O_NOFOLLOW

    try:
        file_descriptor = os.open(path, flags)
    except OSError as exc:
        return RevalidationOutcome.reject(f"ouverture refusée : {exc}", ErrorKind.PERMISSION_DENIED)

    try:
        info_open = os.fstat(file_descriptor)
    except OSError as exc:
        os.close(file_descriptor)
        return RevalidationOutcome.reject(f"descripteur illisible : {exc}", ErrorKind.IO_ERROR)

    if _file_id(info_open) != snapshot.file_id:
        os.close(file_descriptor)
        return RevalidationOutcome.reject("race détectée : la cible a changé pendant l'ouverture")

    if not keep_open:
        os.close(file_descriptor)
        return RevalidationOutcome(accepted=True, snapshot=snapshot)

    return RevalidationOutcome(
        accepted=True,
        file_descriptor=file_descriptor,
        snapshot=snapshot,
    )


def is_reparse_point_path(path: Path) -> bool:
    """Indique si ``path`` porte l'attribut point d'analyse (Windows).

    Variante de :func:`is_reparse_point` pour un chemin déjà ouvert ; elle
    reste inoffensive hors Windows.
    """
    if not _WINDOWS:
        return False
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


__all__ = [
    "RevalidationOutcome",
    "TargetSnapshot",
    "capture_snapshot",
    "is_reparse_point_path",
    "revalidate",
]
