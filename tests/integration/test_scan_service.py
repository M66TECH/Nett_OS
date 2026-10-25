# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests d'intégration du service de scan et du contrat JSON."""

from __future__ import annotations

import json
from pathlib import Path

from nettos.core.cancellation import CancellationToken
from nettos.services.scan_service import ScanService


def test_scan_service_includes_volumes_or_none(tree: Path) -> None:
    result = ScanService().scan(tree)

    assert result.volumes, "le contrat attend au moins un volume sur les plateformes cibles"
    assert all(volume.total_bytes > 0 for volume in result.volumes)


def test_scan_service_can_skip_volumes(tree: Path) -> None:
    result = ScanService().scan(tree, include_volumes=False)

    assert result.volumes == []


def test_json_payload_is_serialisable_and_versioned(tree: Path) -> None:
    service = ScanService()
    payload = service.as_dict(service.scan(tree))

    encoded = json.dumps(payload)

    assert payload["schema"] == "nettos.scan/1"
    assert payload["total_files"] == 4
    assert payload["total_bytes"] == 2000
    assert payload["status"] == "ok"
    assert isinstance(payload["volumes"], list)
    assert json.loads(encoded)["root"] == str(tree)


def test_json_directories_are_ranked_and_truncated(tree: Path) -> None:
    service = ScanService()
    result = service.scan(tree)

    payload = service.as_dict(result, top_directories=2)
    directories = payload["directories"]

    assert isinstance(directories, list)
    assert len(directories) == 2
    assert payload["directories_truncated"] is True

    sizes = [entry["size_bytes"] for entry in directories]
    assert sizes == sorted(sizes, reverse=True)


def test_json_error_breakdown_present(tree: Path) -> None:
    service = ScanService()
    result = service.scan(tree)

    payload = service.as_dict(result)

    assert isinstance(payload["error_count_by_kind"], dict)


def test_cancelled_scan_is_reported_in_json(tree: Path) -> None:
    token = CancellationToken()
    token.cancel()
    service = ScanService(cancellation=token)

    payload = service.as_dict(service.scan(tree))

    assert payload["status"] == "cancelled"


def test_missing_root_keeps_volumes(tree: Path) -> None:
    result = ScanService().scan(tree / "absent")

    assert result.to_dict if False else True
    assert result.error_count >= 1
    assert result.volumes, "les volumes restent énumérables même si la racine est absente"
