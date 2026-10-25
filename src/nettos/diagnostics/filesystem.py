# SPDX-License-Identifier: AGPL-3.0-or-later
"""Détection des liens et points d'analyse à ne pas suivre.

``os.DirEntry.is_symlink()`` ne détecte pas les *junctions* NTFS sous
Windows : ce sont des points d'analyse (reparse points) de type mount
point, et Python les voit comme des répertoires ordinaires. Les parcourir
reviendrait à sortir de l'arborescence autorisée — un risque de sécurité
autant qu'une source de double comptage.

Ce module fournit une détection portable, utilisée par le scanner et, plus
tard, par le moteur de nettoyage.
"""

from __future__ import annotations

import os
import stat
import sys

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
IO_REPARSE_TAG_SYMLINK = 0xA000000C

_WINDOWS = sys.platform.startswith("win")


def is_reparse_point(entry: os.DirEntry[str]) -> bool:
    """Indique si ``entry`` est un point d'analyse Windows.

    Hors Windows, retourne toujours ``False`` : les liens symboliques y
    sont correctement signalés par ``is_symlink()``.
    """
    if not _WINDOWS:
        return False
    try:
        attrs = entry.stat(follow_symlinks=False).st_file_attributes
    except (OSError, AttributeError):
        return False
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def is_link_like(entry: os.DirEntry[str]) -> bool:
    """Indique si ``entry`` est un lien symbolique ou un point d'analyse.

    C'est le prédicat à utiliser partout où une entrée ne doit pas être
    suivie. Il couvre :

    - liens symboliques POSIX et Windows ;
    - junctions NTFS (mount points) ;
    - autres points d'analyse (volumes montés, liens OneDrive, etc.).
    """
    if entry.is_symlink():
        return True
    return is_reparse_point(entry)


def is_regular_file(entry: os.DirEntry[str]) -> bool:
    """Indique si ``entry`` est un fichier ordinaire (jamais un lien suivi)."""
    try:
        mode = entry.stat(follow_symlinks=False).st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode)


def is_regular_directory(entry: os.DirEntry[str]) -> bool:
    """Indique si ``entry`` est un répertoire ordinaire, hors points d'analyse."""
    if is_link_like(entry):
        return False
    try:
        mode = entry.stat(follow_symlinks=False).st_mode
    except OSError:
        return False
    return stat.S_ISDIR(mode)
