# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests des budgets de performance (cahier des charges, section 8.1).

Les budgets officiels visent un million de fichiers sur SSD en 60 s. La CI
n'a pas le temps de générer un million de fichiers pour chaque exécution :
on vérifie donc ici deux propriétés à coût maîtrisé, et un test complet
marqué ``slow`` reste disponible pour une exécution dédiée.

1. **Extrapolation** : le débit mesuré sur 20 000 fichiers tient le budget.
2. **Mémoire** : les agrégats ne conservent pas la liste des fichiers, donc
   la mémoire ne croît pas proportionnellement au nombre de fichiers.
"""

from __future__ import annotations

import os
import time
import tracemalloc
from pathlib import Path

import pytest

from nettos.diagnostics.scanner import StorageScanner

FILES_PER_DIRECTORY = 100


def _build_tree(root: Path, directories: int) -> int:
    """Crée ``directories`` répertoires de 100 petits fichiers chacun."""
    total = 0
    for index in range(directories):
        directory = root / f"dir-{index:04d}"
        directory.mkdir()
        for file_index in range(FILES_PER_DIRECTORY):
            (directory / f"f{file_index:03d}.dat").write_bytes(b"x")
            total += 1
    return total


@pytest.mark.skipif(
    not os.environ.get("NETTOS_SLOW_TESTS"),
    reason="test long : activer avec NETTOS_SLOW_TESTS=1",
)
def test_scan_one_million_files_budget(tmp_path: Path) -> None:
    """Budget officiel : 1 million de fichiers scannés en moins de 60 s.

    La génération de l'arborescence n'est **pas** mesurée : on chronomètre
    uniquement l'appel au scanner. Le budget porte sur le scan, pas sur la
    vitesse du disque de test (une création de 1 M fichiers peut prendre
    plusieurs minutes sur un disque mécanique ou avec un antivirus actif).
    """
    root = tmp_path / "million"
    root.mkdir()
    _build_tree(root, directories=10_000)

    started = time.perf_counter()
    result = StorageScanner().scan(root)
    elapsed = time.perf_counter() - started

    assert result.total_files == 1_000_000
    assert elapsed < 60.0, f"budget dépassé : {elapsed:.1f} s (scan seul)"


def test_scan_throughput_supports_budget(tmp_path: Path) -> None:
    """Extrapolation : le débit mesuré tient le budget de 1 M fichiers / 60 s."""
    root = tmp_path / "bench"
    root.mkdir()
    file_count = _build_tree(root, directories=200)

    started = time.perf_counter()
    result = StorageScanner().scan(root)
    elapsed = time.perf_counter() - started

    assert result.total_files == file_count
    projected = elapsed * (1_000_000 / file_count)
    assert projected < 60.0, f"extrapolation à 1 M fichiers : {projected:.1f} s"


def test_memory_does_not_grow_with_file_count(tmp_path: Path) -> None:
    """La mémoire suit le nombre de répertoires, pas le nombre de fichiers."""
    small = tmp_path / "small"
    small.mkdir()
    _build_tree(small, directories=10)

    large = tmp_path / "large"
    large.mkdir()
    _build_tree(large, directories=40)

    tracemalloc.start()
    try:
        StorageScanner().scan(small)
        tracemalloc.reset_peak()
        base, _ = tracemalloc.get_traced_memory()

        StorageScanner().scan(large)
        peak, _ = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    growth = peak - base
    assert growth < 8 * 1024 * 1024, f"croissance mémoire inattendue : {growth} octets"


def test_directory_aggregation_stays_bounded(tmp_path: Path) -> None:
    """Un répertoire par niveau, pas une entrée par fichier."""
    root = tmp_path / "flat"
    root.mkdir()
    for index in range(5000):
        (root / f"f{index:05d}.dat").write_bytes(b"x")

    result = StorageScanner().scan(root)

    assert result.total_files == 5000
    assert len(result.directories) == 1
