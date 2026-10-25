# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests du moteur de simulation : garanties de sécurité et de non-effet.

Ces tests sont de **sécurité** : une simulation ne doit jamais modifier le
disque, et aucune cible hors racine ne doit être proposée.
"""

from __future__ import annotations

import datetime as dt
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest
from tests.support.symlinks import try_symlink

from nettos.cleaners.rules import CleanerRule, CleanTarget, Platform, RiskLevel
from nettos.cleaners.simulation import SimulationEngine


def _rule(targets: tuple[CleanTarget, ...], **overrides: object) -> CleanerRule:
    params: dict[str, object] = {
        "identifier": "test.simulation.rule",
        "title": "Simulation",
        "description": "règle de test",
        "version": "1",
        "platforms": frozenset({Platform.LINUX, Platform.WINDOWS}),
        "risk": RiskLevel.LOW,
        "targets": targets,
        "valid_from": dt.date(2026, 1, 1),
        "reviewed_on": dt.date(2026, 1, 1),
    }
    params.update(overrides)
    return CleanerRule(**params)  # type: ignore[arg-type]


def _age_files(root: Path, days: int) -> None:
    """Vieillit tous les fichiers sous ``root`` de ``days`` jours."""
    stamp = time.time() - days * 86_400
    for path in root.rglob("*"):
        if path.is_file():
            os.utime(path, (stamp, stamp))


@pytest.fixture
def cache_tree(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "old.log").write_bytes(b"x" * 1000)
    (tmp_path / "app" / "keep.ini").write_bytes(b"y" * 10)
    (tmp_path / "ccache").mkdir()
    (tmp_path / "ccache" / "obj.log").write_bytes(b"z" * 5000)
    _age_files(tmp_path, 30)
    return tmp_path


class TestSimulationBasics:
    def test_collects_matching_files(self, cache_tree: Path) -> None:
        rule = _rule((CleanTarget(pattern="**/*.log", description="journaux"),))

        result = SimulationEngine().simulate(rule, [cache_tree])

        names = {Path(c.path).name for c in result.candidates}
        assert names == {"old.log", "obj.log"}
        assert result.total_bytes == 6000

    def test_ignores_non_matching_files(self, cache_tree: Path) -> None:
        rule = _rule((CleanTarget(pattern="**/*.log", description="journaux"),))

        result = SimulationEngine().simulate(rule, [cache_tree])

        assert all(c.path.endswith(".log") for c in result.candidates)

    def test_exclusions_always_win(self, cache_tree: Path) -> None:
        rule = _rule(
            (CleanTarget(pattern="**/*.log", description="journaux"),),
            excluded=("**/ccache/**",),
        )

        result = SimulationEngine().simulate(rule, [cache_tree])

        assert {Path(c.path).name for c in result.candidates} == {"old.log"}
        assert any("exclu" in r.reason for r in result.rejected)

    def test_missing_root_is_reported(self, tmp_path: Path) -> None:
        rule = _rule((CleanTarget(pattern="**/*", description="tout"),))

        result = SimulationEngine().simulate(rule, [tmp_path / "absent"])

        assert result.missing_roots == [str(tmp_path / "absent")]
        assert result.file_count == 0

    def test_multiple_roots(self, tmp_path: Path) -> None:
        for name in ("a", "b"):
            (tmp_path / name).mkdir()
            (tmp_path / name / "f.log").write_bytes(b"x" * 100)
        rule = _rule((CleanTarget(pattern="**/*.log", description="journaux"),))

        result = SimulationEngine().simulate(rule, [tmp_path / "a", tmp_path / "b"])

        assert result.file_count == 2
        assert result.total_bytes == 200


class TestAgeFiltering:
    def test_old_files_are_candidates(self, cache_tree: Path) -> None:
        rule = _rule((CleanTarget(pattern="**/*.log", description="anciens", max_age_days=7),))

        result = SimulationEngine().simulate(rule, [cache_tree])

        assert result.file_count == 2

    def test_recent_files_are_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "fresh.log").write_bytes(b"x" * 100)
        rule = _rule((CleanTarget(pattern="**/*.log", description="anciens", max_age_days=7),))

        result = SimulationEngine().simulate(rule, [tmp_path])

        assert result.file_count == 0
        assert any("récent" in r.reason for r in result.rejected)

    def test_boundary_age_is_rejected_below_threshold(self, tmp_path: Path) -> None:
        target_file = tmp_path / "edge.log"
        target_file.write_bytes(b"x")
        stamp = time.time() - 6.9 * 86_400
        os.utime(target_file, (stamp, stamp))
        rule = _rule((CleanTarget("**/*.log", "edge", max_age_days=7),))

        result = SimulationEngine().simulate(rule, [tmp_path])

        assert result.file_count == 0


class TestSafetyGuarantees:
    def test_simulation_never_modifies_files(self, cache_tree: Path) -> None:
        before = {
            p: (p.stat().st_size, p.stat().st_mtime) for p in cache_tree.rglob("*") if p.is_file()
        }
        rule = _rule((CleanTarget(pattern="**/*", description="tout"),))

        SimulationEngine().simulate(rule, [cache_tree])

        after = {
            p: (p.stat().st_size, p.stat().st_mtime) for p in cache_tree.rglob("*") if p.is_file()
        }
        assert before == after

    def test_symlinks_are_not_followed(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.log").write_bytes(b"x" * 100)

        if not try_symlink(root / "link", outside, directory=True):
            pytest.skip("liens symboliques indisponibles sur cette plateforme")

        rule = _rule((CleanTarget(pattern="**/*.log", description="journaux"),))
        result = SimulationEngine().simulate(rule, [root])

        assert result.file_count == 0
        assert any("lien" in r.reason for r in result.rejected)

    def test_path_escaping_root_is_rejected(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside.log"
        outside.write_bytes(b"x" * 100)

        if not try_symlink(root / "escape.log", outside):
            pytest.skip("liens symboliques indisponibles sur cette plateforme")

        rule = _rule((CleanTarget(pattern="**/*.log", description="journaux"),))
        result = SimulationEngine().simulate(rule, [root])

        assert all(not c.path.endswith("outside.log") for c in result.candidates)


class TestLimits:
    def test_candidate_limit_truncates(self, tmp_path: Path) -> None:
        for index in range(20):
            (tmp_path / f"f{index:02d}.log").write_bytes(b"x")
        rule = _rule((CleanTarget(pattern="**/*.log", description="journaux"),))

        result = SimulationEngine(max_candidates=5).simulate(rule, [tmp_path])

        assert result.file_count == 5
        assert result.truncated

    def test_entry_limit_truncates(self, tmp_path: Path) -> None:
        for index in range(20):
            (tmp_path / f"f{index:02d}.log").write_bytes(b"x")
        rule = _rule((CleanTarget(pattern="**/*.log", description="journaux"),))

        result = SimulationEngine(max_entries=10).simulate(rule, [tmp_path])

        assert result.truncated

    def test_depth_limit_is_enforced(self, tmp_path: Path) -> None:
        # Windows limite les chemins à 260 caractères : on crée une base
        # courte (sous le répertoire temporaire système) pour atteindre une
        # profondeur de 66 sans dépasser cette limite.
        base = Path(tempfile.mkdtemp(prefix="nd", dir=tempfile.gettempdir()))
        deep = base
        try:
            for _ in range(66):
                deep = deep / "d"
                deep.mkdir()
            (deep / "deep.log").write_bytes(b"x")

            rule = _rule((CleanTarget(pattern="**/*.log", description="journaux"),))
            result = SimulationEngine().simulate(rule, [base])
        finally:
            shutil.rmtree(base, ignore_errors=True)

        assert result.file_count == 0
        assert any("profondeur" in r.reason for r in result.rejected)


@pytest.mark.skipif(sys.platform.startswith("win"), reason="chmod POSIX seulement")
def test_permission_error_is_reported_not_raised(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "f.log").write_bytes(b"x")
    os.chmod(locked, 0o000)
    try:
        rule = _rule((CleanTarget(pattern="**/*.log", description="journaux"),))
        result = SimulationEngine().simulate(rule, [tmp_path])
    finally:
        os.chmod(locked, 0o700)

    assert any("illisible" in r.reason for r in result.rejected)
