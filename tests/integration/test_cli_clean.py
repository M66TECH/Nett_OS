# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests d'intégration des commandes ``clean``, ``quarantine`` et ``history``."""

from __future__ import annotations

import json
from pathlib import Path

from nettos.cli.main import (
    EXIT_NEEDS_CONFIRMATION,
    EXIT_OK,
    EXIT_USAGE,
    main,
)


def _is_windows() -> bool:
    import sys

    return sys.platform.startswith("win")


def _active_rule() -> str:
    return "windows.user.temp" if _is_windows() else "linux.user.thumbnails"


class TestCleanCommand:
    def test_clean_defaults_to_dry_run(self, tmp_path: Path, capsys) -> None:
        exit_code = main(["clean", _active_rule(), "--quarantine-dir", str(tmp_path / "q")])

        out = capsys.readouterr().out

        assert exit_code == EXIT_OK
        assert "dry-run" in out
        assert "Aucune modification" in out

    def test_clean_confirm_requires_rule(self, tmp_path: Path, capsys) -> None:
        exit_code = main(["clean", "--confirm", "--quarantine-dir", str(tmp_path / "q")])

        err = capsys.readouterr().err

        assert exit_code == EXIT_USAGE
        assert "--confirm" in err

    def test_clean_json_schema(self, tmp_path: Path, capsys) -> None:
        main(
            [
                "clean",
                _active_rule(),
                "--json",
                "--quarantine-dir",
                str(tmp_path / "q"),
            ]
        )

        payload = json.loads(capsys.readouterr().out)

        assert payload["schema"] == "nettos.clean/1"
        assert payload["mode"] == "dry-run"
        assert "theoretical_bytes" in payload
        assert "reclaimed_bytes" in payload

    def test_clean_unknown_rule(self, tmp_path: Path, capsys) -> None:
        exit_code = main(["clean", "nope.nope", "--quarantine-dir", str(tmp_path / "q")])

        assert exit_code == EXIT_USAGE
        assert "inconnue" in capsys.readouterr().err

    def test_clean_inactive_rule_is_refused(self, tmp_path: Path, capsys) -> None:
        inactive = "linux.user.cache" if _is_windows() else "windows.user.temp"
        exit_code = main(["clean", inactive, "--quarantine-dir", str(tmp_path / "q")])

        assert exit_code == EXIT_USAGE
        assert "pas actif" in capsys.readouterr().err


class TestQuarantineCommand:
    def test_empty_quarantine(self, tmp_path: Path, capsys) -> None:
        exit_code = main(["quarantine", "list", "--quarantine-dir", str(tmp_path / "q")])

        assert exit_code == EXIT_OK
        assert "vide" in capsys.readouterr().out.lower()

    def test_quarantine_json(self, tmp_path: Path, capsys) -> None:
        main(["quarantine", "list", "--json", "--quarantine-dir", str(tmp_path / "q")])

        payload = json.loads(capsys.readouterr().out)

        assert payload == []

    def test_purge_requires_yes(self, tmp_path: Path, capsys) -> None:
        exit_code = main(["quarantine", "purge", "--quarantine-dir", str(tmp_path / "q")])

        assert exit_code == EXIT_NEEDS_CONFIRMATION
        assert "--yes" in capsys.readouterr().err

    def test_purge_with_yes(self, tmp_path: Path, capsys) -> None:
        exit_code = main(["quarantine", "purge", "--yes", "--quarantine-dir", str(tmp_path / "q")])

        assert exit_code == EXIT_OK
        assert "Purge" in capsys.readouterr().out

    def test_restore_requires_entry(self, tmp_path: Path, capsys) -> None:
        exit_code = main(["quarantine", "restore", "--quarantine-dir", str(tmp_path / "q")])

        assert exit_code == EXIT_USAGE
        assert "identifiant" in capsys.readouterr().err

    def test_restore_unknown_entry(self, tmp_path: Path, capsys) -> None:
        exit_code = main(
            [
                "quarantine",
                "restore",
                "deadbeef",
                "--quarantine-dir",
                str(tmp_path / "q"),
            ]
        )

        assert exit_code == EXIT_USAGE
        assert "impossible" in capsys.readouterr().err


class TestHistoryCommand:
    def test_history_requires_audit_db(self, tmp_path: Path, monkeypatch, capsys) -> None:
        from nettos.persistence import audit_log

        monkeypatch.setattr(audit_log, "default_audit_path", lambda: tmp_path / "a.sqlite3")

        exit_code = main(["history"])

        assert exit_code == EXIT_OK
        assert "vide" in capsys.readouterr().out.lower()

    def test_history_json(self, tmp_path: Path, monkeypatch, capsys) -> None:
        from nettos.persistence import audit_log

        monkeypatch.setattr(audit_log, "default_audit_path", lambda: tmp_path / "a.sqlite3")

        main(["history", "--json"])

        payload = json.loads(capsys.readouterr().out)

        assert payload == []

    def test_history_purge_requires_yes(self, tmp_path: Path, monkeypatch, capsys) -> None:
        from nettos.persistence import audit_log

        monkeypatch.setattr(audit_log, "default_audit_path", lambda: tmp_path / "a.sqlite3")

        exit_code = main(["history", "--purge"])

        assert exit_code == EXIT_NEEDS_CONFIRMATION
        assert "--yes" in capsys.readouterr().err


class TestCommandRegistration:
    def test_all_commands_are_registered(self) -> None:
        from nettos.cli.main import build_parser

        for command in ("scan", "rules", "plan", "clean", "quarantine", "history"):
            assert build_parser().parse_args([command]).command == command
