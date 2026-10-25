# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests des adaptateurs de plateforme.

Les adaptateurs sont testés sans dépendre du matériel : on vérifie le
contrat, le classement des volumes et l'analyse des points de montage.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from nettos.adapters import create_adapter, current_platform_name, get_platform_adapter
from nettos.adapters.base import PlatformAdapter
from nettos.adapters.linux import LinuxAdapter, _unescape_octal
from nettos.core.errors import UnsupportedPlatformError


def test_create_linux_adapter() -> None:
    adapter = create_adapter("linux")

    assert adapter.name == "linux"
    assert isinstance(adapter, PlatformAdapter)


def test_create_windows_adapter() -> None:
    adapter = create_adapter("windows")

    assert adapter.name == "windows"
    assert isinstance(adapter, PlatformAdapter)


def test_unknown_platform_is_rejected() -> None:
    with pytest.raises(UnsupportedPlatformError):
        create_adapter("plan9")


def test_current_platform_matches_host() -> None:
    name = current_platform_name()

    if sys.platform.startswith("linux"):
        assert name == "linux"
    elif sys.platform.startswith("win"):
        assert name == "windows"


def test_get_adapter_returns_contract() -> None:
    adapter = get_platform_adapter()

    assert isinstance(adapter, PlatformAdapter)
    assert adapter.name in {"linux", "windows"}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/home/user", "/home/user"),
        ("/mnt/My\\040Disk", "/mnt/My Disk"),
        ("/mnt/caf\\303\\251", "/mnt/café"),
        ("/mnt/a\\134b", "/mnt/a\\b"),
        ("", ""),
        ("/mnt/trailing\\04", "/mnt/trailing\\04"),
    ],
)
def test_unescape_octal(raw: str, expected: str) -> None:
    assert _unescape_octal(raw) == expected


def test_linux_parse_mounts_skips_malformed_lines() -> None:
    raw = "\n".join(
        [
            "/dev/sda1 / ext4 rw,relatime 0 0",
            "garbage",
            "",
            "proc /proc proc rw 0 0",
            "tmpfs /run tmpfs rw 0 0",
        ]
    )

    entries = LinuxAdapter._parse_mounts(raw)

    assert ("/", "ext4") in entries
    assert ("/proc", "proc") in entries
    assert ("/run", "tmpfs") in entries
    assert len(entries) == 3


def test_linux_volumes_are_sorted_and_real() -> None:
    if not sys.platform.startswith("linux"):
        pytest.skip("spécifique Linux")

    volumes = LinuxAdapter().list_volumes()

    assert volumes, "au moins le volume racine doit être détecté"
    mount_points = [v.mount_point for v in volumes]
    assert mount_points == sorted(mount_points)
    for volume in volumes:
        assert volume.total_bytes > 0
        assert volume.free_bytes >= 0
        assert 0.0 <= volume.used_ratio <= 1.0


def test_linux_pseudo_filesystems_are_excluded() -> None:
    if not sys.platform.startswith("linux"):
        pytest.skip("spécifique Linux")

    filesystems = {v.filesystem for v in LinuxAdapter().list_volumes()}

    assert "proc" not in filesystems
    assert "sysfs" not in filesystems


def test_windows_volumes_are_real() -> None:
    if not sys.platform.startswith("win"):
        pytest.skip("spécifique Windows")

    from nettos.adapters.windows import WindowsAdapter

    volumes = WindowsAdapter().list_volumes()

    assert volumes, "au moins le lecteur système doit être détecté"
    for volume in volumes:
        assert volume.mount_point.endswith(":\\")
        assert volume.total_bytes > 0
        assert volume.used_bytes + volume.free_bytes <= volume.total_bytes


def test_windows_drives_are_letter_prefixed() -> None:
    if not sys.platform.startswith("win"):
        pytest.skip("spécifique Windows")

    from nettos.adapters.windows import WindowsAdapter

    for drive in WindowsAdapter()._drives():
        assert drive[1:] == ":\\"


def test_temp_dir_is_absolute() -> None:
    adapter = get_platform_adapter()

    assert Path(adapter.temp_dir()).is_absolute()
    assert Path(adapter.user_cache_dir()).is_absolute()
