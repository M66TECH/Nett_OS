# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fabrique de liens symboliques pour les tests.

Regroupée ici pour que les tests unitaires et de sécurité utilisent le
même mécanisme de repli (``mklink`` sous Windows sans mode développeur).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def try_symlink(link: Path, target: Path, *, directory: bool = False) -> bool:
    """Crée un lien symbolique et retourne ``True`` en cas de succès.

    Retourne ``False`` lorsque le système refuse la création (Windows sans
    mode développeur ni privilège administrateur, système de fichiers non
    compatible). Les tests doivent alors être ignorés, pas contournés.
    """
    try:
        link.symlink_to(target, target_is_directory=directory)
        return True
    except (OSError, NotImplementedError):
        pass

    if sys.platform.startswith("win") and directory:
        try:
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True,
                check=False,
            )
            return result.returncode == 0
        except OSError:
            return False

    return False
