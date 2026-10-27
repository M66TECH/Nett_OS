# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests de sécurité du pipeline d'exécution contrôlée (section 6.1).

Chaque point de décision est vérifié : sans confirmation rien n'est touché,
une race est détectée, une cible hors périmètre est ignorée, et l'espace
réellement récupéré est mesuré séparément de l'estimation.
"""

from __future__ import annotations

import datetime as dt
import os
import time
from pathlib import Path

import pytest
from tests.support.symlinks import try_symlink

from nettos.cleaners.declarative import DeclarativeCleaner
from nettos.cleaners.quarantine import Quarantine
from nettos.cleaners.rules import CleanerRule, CleanTarget, Platform, RiskLevel
from nettos.cleaners.simulation import SimulationEngine
from nettos.persistence.audit_log import AuditLog
from nettos.services.clean_service import (
    CleanExecutionService,
    ExecutionMode,
    TargetOutcome,
)

RULE = CleanerRule(
    identifier="test.exec.rule",
    title="Règle d'exécution",
    description="fichiers .log anciens",
    version="1",
    platforms=frozenset({Platform.LINUX, Platform.WINDOWS}),
    risk=RiskLevel.LOW,
    targets=(CleanTarget(pattern="**/*.log", description="journaux"),),
    valid_from=dt.date(2026, 1, 1),
    reviewed_on=dt.date(2026, 1, 1),
)


class FakeCleaner(DeclarativeCleaner):
    """Nettoyeur pointé sur un répertoire de test."""

    RULE = RULE

    def __init__(self, root: Path) -> None:
        super().__init__()
        self._root = root

    def roots(self) -> list[Path]:
        return [self._root]


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    root = tmp_path / "sandbox"
    root.mkdir()
    for index in range(3):
        (root / f"f{index}.log").write_bytes(b"x" * 100)
    (root / "keep.txt").write_bytes(b"y" * 50)
    return root


@pytest.fixture
def service(tmp_path: Path) -> tuple[CleanExecutionService, Quarantine, AuditLog]:
    quarantine = Quarantine(tmp_path / "quarantine")
    audit = AuditLog(tmp_path / "audit.sqlite3")
    executor = CleanExecutionService(quarantine=quarantine, audit=audit)
    yield executor, quarantine, audit
    audit.close()


class TestDryRun:
    def test_dry_run_touches_nothing(self, sandbox: Path, service) -> None:
        executor, _, _ = service

        report = executor.execute(FakeCleaner(sandbox), mode=ExecutionMode.DRY_RUN)

        assert report.processed == 0
        assert len(list(sandbox.glob("*.log"))) == 3
        assert report.theoretical_bytes == 300

    def test_dry_run_marks_targets_as_planned(self, sandbox: Path, service) -> None:
        executor, _, _ = service

        report = executor.execute(FakeCleaner(sandbox), mode=ExecutionMode.DRY_RUN)

        assert all(item.outcome is TargetOutcome.PLANNED for item in report.results)

    def test_dry_run_creates_no_quarantine_entry(self, sandbox: Path, service) -> None:
        executor, quarantine, _ = service

        executor.execute(FakeCleaner(sandbox), mode=ExecutionMode.DRY_RUN)

        assert quarantine.entries() == []


class TestConfirmationGate:
    def test_execute_without_confirm_touches_nothing(self, sandbox: Path, service) -> None:
        executor, _, _ = service

        report = executor.execute(FakeCleaner(sandbox), mode=ExecutionMode.EXECUTE)

        assert report.status == "needs_confirmation"
        assert report.processed == 0
        assert len(list(sandbox.glob("*.log"))) == 3

    def test_execute_without_confirm_creates_no_entry(self, sandbox: Path, service) -> None:
        executor, quarantine, _ = service

        executor.execute(FakeCleaner(sandbox), mode=ExecutionMode.EXECUTE)

        assert quarantine.entries() == []

    def test_execute_with_confirm_acts(self, sandbox: Path, service) -> None:
        executor, _, _ = service

        report = executor.execute(FakeCleaner(sandbox), mode=ExecutionMode.EXECUTE, confirm=True)

        assert report.processed == 3
        assert report.quarantined == 3
        assert not list(sandbox.glob("*.log"))


class TestScopeRespect:
    def test_non_matching_files_are_untouched(self, sandbox: Path, service) -> None:
        executor, _, _ = service

        executor.execute(FakeCleaner(sandbox), mode=ExecutionMode.EXECUTE, confirm=True)

        assert (sandbox / "keep.txt").is_file()

    def test_target_outside_root_is_rejected(self, tmp_path: Path, service) -> None:
        executor, _, _ = service
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside.log"
        outside.write_bytes(b"x" * 10)

        cleaner = FakeCleaner(root)
        simulation = SimulationEngine().simulate(
            RULE,
            [root],
        )
        # Force une cible hors périmètre pour vérifier le refus.
        from nettos.cleaners.base import CandidateFile

        simulation.candidates.append(
            CandidateFile(path=str(outside), size_bytes=10, modified_at=time.time(), age_days=0)
        )

        report = executor.execute(
            cleaner,
            mode=ExecutionMode.EXECUTE,
            confirm=True,
            simulation=simulation,
        )

        assert outside.is_file()
        assert any(item.outcome is TargetOutcome.REJECTED for item in report.results)

    def test_file_removed_after_simulation_is_rejected(self, sandbox: Path, service) -> None:
        executor, _, _ = service
        cleaner = FakeCleaner(sandbox)
        simulation = cleaner.simulate()
        victim = sandbox / "f0.log"
        victim.unlink()

        report = executor.execute(
            cleaner, mode=ExecutionMode.EXECUTE, confirm=True, simulation=simulation
        )

        rejected = [r for r in report.results if r.outcome is TargetOutcome.REJECTED]
        assert rejected
        assert report.processed == 2

    def test_file_modified_after_simulation_is_rejected(self, sandbox: Path, service) -> None:
        executor, _, _ = service
        cleaner = FakeCleaner(sandbox)
        simulation = cleaner.simulate()
        victim = sandbox / "f0.log"
        victim.write_bytes(b"changed content after simulation")

        report = executor.execute(
            cleaner, mode=ExecutionMode.EXECUTE, confirm=True, simulation=simulation
        )

        rejected = [r for r in report.results if r.outcome is TargetOutcome.REJECTED]
        assert rejected
        assert victim.exists(), "une cible modifiée ne doit jamais être supprimée"

    def test_symlink_substitution_is_rejected(self, sandbox: Path, service) -> None:
        executor, _, _ = service
        cleaner = FakeCleaner(sandbox)
        simulation = cleaner.simulate()
        victim = sandbox / "f0.log"
        sensitive = sandbox / "keep.txt"
        victim.unlink()
        if not try_symlink(victim, sensitive):
            pytest.skip("liens symboliques indisponibles")

        report = executor.execute(
            cleaner, mode=ExecutionMode.EXECUTE, confirm=True, simulation=simulation
        )

        assert sensitive.exists(), "la cible d'un lien ne doit jamais être supprimée"
        assert any(r.outcome is TargetOutcome.REJECTED for r in report.results)


class TestQuarantineIntegration:
    def test_files_are_restorable(self, sandbox: Path, service) -> None:
        executor, quarantine, _ = service

        executor.execute(FakeCleaner(sandbox), mode=ExecutionMode.EXECUTE, confirm=True)
        entries = quarantine.entries()
        assert len(entries) == 3

        quarantine.restore(entries[0].entry_id)

        assert Path(entries[0].original_path).is_file()

    def test_quarantine_metadata_matches_rule(self, sandbox: Path, service) -> None:
        executor, quarantine, _ = service

        executor.execute(FakeCleaner(sandbox), mode=ExecutionMode.EXECUTE, confirm=True)

        entry = quarantine.entries()[0]
        assert entry.rule_identifier == "test.exec.rule"
        assert entry.rule_version == "1"
        assert entry.sha256 is not None


class TestMeasurement:
    def test_reclaimed_bytes_are_measured(self, sandbox: Path, service) -> None:
        executor, _, _ = service

        report = executor.execute(FakeCleaner(sandbox), mode=ExecutionMode.EXECUTE, confirm=True)

        assert report.reclaimed_bytes == 300
        assert report.theoretical_bytes == 300
        assert report.space_difference == 0

    def test_partial_reclaim_is_reported(self, sandbox: Path, service) -> None:
        executor, _, _ = service
        cleaner = FakeCleaner(sandbox)
        simulation = cleaner.simulate()
        (sandbox / "f1.log").unlink()

        report = executor.execute(
            cleaner, mode=ExecutionMode.EXECUTE, confirm=True, simulation=simulation
        )

        assert report.reclaimed_bytes < report.theoretical_bytes
        assert report.space_difference > 0


class TestAuditIntegration:
    def test_operation_is_recorded(self, sandbox: Path, service) -> None:
        executor, _, audit = service

        report = executor.execute(FakeCleaner(sandbox), mode=ExecutionMode.EXECUTE, confirm=True)

        operations = audit.operations()
        assert len(operations) == 1
        assert operations[0].operation_id == report.operation_id
        assert operations[0].status == "completed"

    def test_targets_are_recorded(self, sandbox: Path, service) -> None:
        executor, _, audit = service

        report = executor.execute(FakeCleaner(sandbox), mode=ExecutionMode.EXECUTE, confirm=True)

        targets = audit.targets(report.operation_id)
        assert len(targets) == 3
        assert all(target.outcome == "quarantined" for target in targets)

    def test_rejections_are_recorded(self, sandbox: Path, service) -> None:
        executor, _, audit = service
        cleaner = FakeCleaner(sandbox)
        simulation = cleaner.simulate()
        (sandbox / "f0.log").unlink()

        report = executor.execute(
            cleaner, mode=ExecutionMode.EXECUTE, confirm=True, simulation=simulation
        )

        targets = audit.targets(report.operation_id)
        assert any(target.outcome == "rejected" for target in targets)

    def test_errors_are_summarised(self, sandbox: Path, service) -> None:
        executor, _, audit = service
        cleaner = FakeCleaner(sandbox)
        simulation = cleaner.simulate()
        (sandbox / "f0.log").unlink()

        report = executor.execute(
            cleaner, mode=ExecutionMode.EXECUTE, confirm=True, simulation=simulation
        )

        operation = audit.operations()[0]
        assert operation.error_summary
        assert operation.failed == 0
        assert report.error_summary


class TestLimits:
    def test_max_targets_limits_processing(self, sandbox: Path, service) -> None:
        executor, _, _ = service

        report = executor.execute(
            FakeCleaner(sandbox),
            mode=ExecutionMode.EXECUTE,
            confirm=True,
            max_targets=1,
        )

        assert report.status == "truncated"
        assert report.processed == 1
        assert len(list(sandbox.glob("*.log"))) == 2


class TestNoAuditLog:
    def test_works_without_audit(self, sandbox: Path, tmp_path: Path) -> None:
        executor = CleanExecutionService(quarantine=Quarantine(tmp_path / "q"))

        report = executor.execute(FakeCleaner(sandbox), mode=ExecutionMode.EXECUTE, confirm=True)

        assert report.processed == 3
        assert report.reclaimed_bytes == 300


@pytest.mark.skipif(not os.access(Path.home(), os.W_OK), reason="profil non inscriptible")
def test_simulation_then_execution_on_empty_dir(tmp_path: Path) -> None:
    """Un répertoire vide ne produit ni action ni erreur."""
    root = tmp_path / "empty"
    root.mkdir()
    executor = CleanExecutionService(quarantine=Quarantine(tmp_path / "q"))

    report = executor.execute(FakeCleaner(root), mode=ExecutionMode.EXECUTE, confirm=True)

    assert report.processed == 0
    assert report.status == "completed"
