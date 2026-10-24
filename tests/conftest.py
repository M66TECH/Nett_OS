# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fixtures communes aux tests NettOS.

Aucune fixture ne dépend de l'interface graphique : le moteur doit se
tester sans Qt (cahier des charges, section 4.2, règle 7).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """Arborescence de test avec fichiers, sous-répertoire et fichier vide."""
    (tmp_path / "a.txt").write_bytes(b"x" * 100)
    (tmp_path / "empty.txt").write_bytes(b"")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.bin").write_bytes(b"y" * 900)
    nested = sub / "nested"
    nested.mkdir()
    (nested / "c.bin").write_bytes(b"z" * 1000)
    return tmp_path
