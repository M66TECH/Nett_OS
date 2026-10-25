# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests d'intégration des commandes ``rules`` et ``plan``."""

from __future__ import annotations

import json

import pytest

from nettos.cli.main import main


def test_rules_lists_active_rules(capsys) -> None:
    exit_code = main(["rules"])

    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Plateforme" in out
    assert "Règles" in out


def test_rules_json_is_valid(capsys) -> None:
    exit_code = main(["rules", "--json"])

    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert isinstance(payload, list)
    assert payload
    entry = payload[0]
    assert {"identifier", "title", "risk", "status", "targets"} <= set(entry)


def test_rules_json_includes_all_platforms_with_flag(capsys) -> None:
    main(["rules", "--json", "--all"])

    payload = json.loads(capsys.readouterr().out)

    platforms = {entry["identifier"].split(".")[0] for entry in payload if entry["identifier"]}
    assert "linux" in platforms
    assert "windows" in platforms


def test_rules_risk_filter(capsys) -> None:
    main(["rules", "--json", "--risk", "moderate"])

    payload = json.loads(capsys.readouterr().out)

    assert payload
    for entry in payload:
        assert entry["risk"] in {"moderate", "high"}


def test_plan_unknown_rule_exits_with_usage_error(capsys) -> None:
    exit_code = main(["plan", "does.not.exist"])

    err = capsys.readouterr().err

    assert exit_code == 2
    assert "inconnue" in err


def test_plan_inactive_rule_is_refused(capsys) -> None:
    exit_code = main(["plan", "linux.user.cache"])

    err = capsys.readouterr().err

    assert exit_code == 2
    assert "pas actif" in err


def test_plan_reports_read_only(tmp_path, capsys) -> None:
    marker = tmp_path / "should_survive.txt"
    marker.write_text("intact")

    main(["plan", "windows.user.temp"] if _is_windows() else ["plan", "linux.user.thumbnails"])

    out = capsys.readouterr().out

    assert "Aucune suppression" in out
    assert marker.read_text() == "intact"


def test_plan_json_schema(capsys) -> None:
    identifier = "windows.user.temp" if _is_windows() else "linux.user.thumbnails"
    main(["plan", identifier, "--json"])

    payload = json.loads(capsys.readouterr().out)

    assert payload["schema"] == "nettos.plan/1"
    assert payload["rule"] == identifier
    assert "file_count" in payload
    assert "candidates" in payload
    assert "rejected" in payload


def test_plan_all_active_rules_json(capsys) -> None:
    main(["plan", "--json"])

    payload = json.loads(capsys.readouterr().out)

    assert isinstance(payload, list)
    assert payload
    assert all(item["schema"] == "nettos.plan/1" for item in payload)


def test_plan_never_deletes_files(tmp_path, monkeypatch, capsys) -> None:
    """Le plan ne supprime rien, même quand des cibles existent."""
    fake_home = tmp_path / "home"
    temp_dir = fake_home / "AppData" / "Local" / "Temp"
    temp_dir.mkdir(parents=True)
    target = temp_dir / "old.tmp"
    target.write_bytes(b"x" * 100)
    import os
    import time

    old = time.time() - 30 * 86_400
    os.utime(target, (old, old))

    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))

    main(["plan"])

    assert target.exists(), "le plan ne doit jamais supprimer un fichier"


def test_no_command_prints_help(capsys) -> None:
    exit_code = main([])

    out = capsys.readouterr().out

    assert exit_code == 0
    assert "rules" in out
    assert "plan" in out


def _is_windows() -> bool:
    import sys

    return sys.platform.startswith("win")


@pytest.mark.parametrize("command", ["scan", "rules", "plan"])
def test_commands_are_registered(command: str) -> None:
    from nettos.cli.main import build_parser

    args = build_parser().parse_args([command])

    assert args.command == command
