# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests d'intégration de la ligne de commande (headless)."""

from __future__ import annotations

import json

from nettos.cli.main import main


def test_scan_json_outputs_valid_payload(tree, capsys) -> None:
    exit_code = main(["scan", str(tree), "--json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["status"] == "ok"
    assert payload["total_files"] == 4
    assert payload["total_bytes"] == 2000
    assert payload["error_count"] == 0


def test_scan_human_output_mentions_totals(tree, capsys) -> None:
    exit_code = main(["scan", str(tree)])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Fichiers" in captured.out
    assert "2000" in captured.out


def test_scan_missing_directory_returns_error_code(tmp_path, capsys) -> None:
    exit_code = main(["scan", str(tmp_path / "nope"), "--json"])

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "introuvable" in captured.err


def test_no_command_prints_help(capsys) -> None:
    exit_code = main([])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "nettos" in captured.out.lower()
