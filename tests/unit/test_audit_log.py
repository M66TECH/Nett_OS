# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests du journal d'audit local et de sa politique de confidentialité."""

from __future__ import annotations

import datetime as dt
import sqlite3
from pathlib import Path

import pytest

from nettos.persistence.audit_log import (
    SCHEMA_VERSION,
    AuditLog,
    TargetRecord,
    default_audit_path,
)


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    log = AuditLog(tmp_path / "audit.sqlite3")
    yield log
    log.close()


def _operation(audit: AuditLog, operation_id: str = "op1", **overrides: object) -> None:
    params: dict[str, object] = {
        "operation_id": operation_id,
        "rule_identifier": "test.rule",
        "rule_version": "1",
        "mode": "execute",
        "targets": 3,
        "theoretical_bytes": 1000,
    }
    params.update(overrides)
    audit.start_operation(**params)  # type: ignore[arg-type]


class TestSchema:
    def test_schema_is_created(self, tmp_path: Path) -> None:
        path = tmp_path / "a.sqlite3"
        with AuditLog(path) as log:
            assert log.path == path

        connection = sqlite3.connect(str(path))
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        connection.close()

        assert {"operations", "operation_targets", "schema_info"} <= tables

    def test_schema_version_is_recorded(self, audit: AuditLog) -> None:
        connection = sqlite3.connect(str(audit.path))
        version = connection.execute("SELECT version FROM schema_info").fetchone()[0]
        connection.close()

        assert version == SCHEMA_VERSION

    def test_reopening_preserves_data(self, tmp_path: Path) -> None:
        path = tmp_path / "a.sqlite3"
        with AuditLog(path) as log:
            _operation(log)

        with AuditLog(path) as log:
            assert len(log.operations()) == 1


class TestOperations:
    def test_start_and_finish(self, audit: AuditLog) -> None:
        _operation(audit)

        audit.finish_operation(
            "op1",
            status="completed",
            processed=2,
            quarantined=2,
            failed=1,
            reclaimed_bytes=900,
            error_summary={"not_found": 1},
        )

        operations = audit.operations()
        assert len(operations) == 1
        record = operations[0]
        assert record.status == "completed"
        assert record.processed == 2
        assert record.reclaimed_bytes == 900
        assert record.error_summary == {"not_found": 1}
        assert record.finished_at is not None

    def test_operations_are_newest_first(self, audit: AuditLog) -> None:
        connection = sqlite3.connect(str(audit.path))
        connection.execute(
            """
            INSERT INTO operations (operation_id, started_at, rule_identifier,
                rule_version, mode, status) VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("old", "2020-01-01T00:00:00+00:00", "r", "1", "execute", "completed"),
        )
        connection.commit()
        connection.close()
        _operation(audit, "new")

        operations = audit.operations()

        assert operations[0].operation_id == "new"

    def test_limit_is_applied(self, audit: AuditLog) -> None:
        for index in range(5):
            _operation(audit, f"op{index}")

        assert len(audit.operations(limit=2)) == 2


class TestTargets:
    def test_targets_are_recorded(self, audit: AuditLog) -> None:
        _operation(audit)
        audit.record_target(
            "op1", path="/a/b.txt", outcome="quarantined", reason="entrée 1", size_bytes=42
        )

        targets = audit.targets("op1")

        assert len(targets) == 1
        assert targets[0].path == "/a/b.txt"
        assert targets[0].size_bytes == 42

    def test_record_targets_bulk(self, audit: AuditLog) -> None:
        _operation(audit)
        audit.record_targets(
            [
                TargetRecord("op1", "/a.txt", "quarantined", "", 10),
                TargetRecord("op1", "/b.txt", "rejected", "disparu", 0),
            ]
        )

        assert len(audit.targets("op1")) == 2

    def test_targets_of_other_operation_are_separate(self, audit: AuditLog) -> None:
        _operation(audit, "op1")
        _operation(audit, "op2")
        audit.record_target("op1", path="/a.txt", outcome="quarantined")
        audit.record_target("op2", path="/b.txt", outcome="quarantined")

        assert [t.path for t in audit.targets("op1")] == ["/a.txt"]


class TestPrivacyPolicy:
    def test_schema_has_no_content_column(self, audit: AuditLog) -> None:
        """Le journal ne stocke jamais le contenu des fichiers (section 5.2)."""
        connection = sqlite3.connect(str(audit.path))
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(operation_targets)").fetchall()
        }
        operation_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(operations)").fetchall()
        }
        connection.close()

        forbidden = {"content", "data", "bytes", "blob", "checksum"}
        assert not (columns & forbidden)
        assert not (operation_columns & forbidden)

    def test_module_has_no_network_imports(self) -> None:
        import nettos.persistence.audit_log as module

        source = Path(module.__file__).read_text(encoding="utf-8")
        for banned in ("import socket", "import urllib", "import requests", "import http"):
            assert banned not in source


class TestPurge:
    def test_purge_all(self, audit: AuditLog) -> None:
        for index in range(3):
            _operation(audit, f"op{index}")
            audit.record_target(f"op{index}", path="/x", outcome="quarantined")

        removed = audit.purge()

        assert removed == 3
        assert audit.operations() == []

    def test_purge_by_age(self, audit: AuditLog) -> None:
        connection = sqlite3.connect(str(audit.path))
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=90)).isoformat()
        connection.execute(
            """
            INSERT INTO operations (operation_id, started_at, rule_identifier,
                rule_version, mode, status) VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("old", old, "r", "1", "execute", "completed"),
        )
        connection.commit()
        connection.close()
        _operation(audit, "recent")

        removed = audit.purge(older_than_days=30)

        assert removed == 1
        assert [op.operation_id for op in audit.operations()] == ["recent"]


class TestDefaults:
    def test_default_path_is_absolute(self) -> None:
        path = default_audit_path()

        assert path.is_absolute()
        assert "NettOS" in str(path)
