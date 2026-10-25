# SPDX-License-Identifier: AGPL-3.0-or-later
"""Adaptateur Windows : lecteurs logiques et espace disponible.

Lecture seule, sans dépendance externe : le répertoire des lecteurs est
obtenu via ``GetLogicalDrives`` et l'espace via ``GetDiskFreeSpaceExW``,
tous deux exposés par ``kernel32`` et appelés avec ``ctypes``.

Les fichiers temporaires et chemins système de Windows sont centralisés
ici pour que le cœur n'ait jamais à tester ``sys.platform`` lui-même.
"""

from __future__ import annotations

import ctypes
import os
import string
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path

from nettos.adapters.base import PlatformAdapter
from nettos.core.result import VolumeInfo

DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

_USABLE_DRIVE_TYPES = frozenset({DRIVE_FIXED, DRIVE_REMOTE, DRIVE_REMOVABLE})

_DRIVE_TYPE_LABELS = {
    0: "unknown",
    1: "no-root-dir",
    2: "removable",
    3: "fixed",
    4: "remote",
    5: "cdrom",
    6: "ramdisk",
}


class WindowsAdapter(PlatformAdapter):
    """Adaptateur pour Windows 10 et 11."""

    @property
    def name(self) -> str:
        return "windows"

    def list_volumes(self) -> list[VolumeInfo]:
        """Retourne les lecteurs utilisables, avec leur espace disponible."""
        volumes: list[VolumeInfo] = []
        for root in self._drives():
            drive_type = self._drive_type(root)
            if drive_type not in _USABLE_DRIVE_TYPES:
                continue
            info = self._volume_info(root, drive_type)
            if info is not None:
                volumes.append(info)
        volumes.sort(key=lambda v: v.mount_point)
        return volumes

    def _drives(self) -> list[str]:
        """Liste des lecteurs logiques présents (``C:\\``, ``D:\\``…)."""
        if not sys.platform.startswith("win"):
            return []
        try:
            mask = ctypes.windll.kernel32.GetLogicalDrives()
        except AttributeError:
            return []
        drives: list[str] = []
        for index, letter in enumerate(string.ascii_uppercase):
            if mask & (1 << index):
                drives.append(f"{letter}:\\")
        return drives

    @staticmethod
    def _drive_type(root: str) -> int:
        try:
            return int(ctypes.windll.kernel32.GetDriveTypeW(root))
        except AttributeError:
            return 0

    @staticmethod
    def _volume_info(root: str, drive_type: int) -> VolumeInfo | None:
        """Interroge ``GetDiskFreeSpaceExW`` pour un lecteur."""
        free_bytes = wintypes.ULARGE_INTEGER()
        total_bytes = wintypes.ULARGE_INTEGER()
        total_free = wintypes.ULARGE_INTEGER()
        try:
            ok = ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(root),
                ctypes.byref(free_bytes),
                ctypes.byref(total_bytes),
                ctypes.byref(total_free),
            )
        except AttributeError:
            ok = 0
        if not ok:
            return None

        total = int(total_bytes.value)
        free = int(total_free.value)
        return VolumeInfo(
            mount_point=root,
            total_bytes=total,
            used_bytes=max(total - free, 0),
            free_bytes=free,
            filesystem=_DRIVE_TYPE_LABELS.get(drive_type),
        )

    def user_cache_dir(self) -> Path:
        """Répertoire de cache utilisateur (``%LOCALAPPDATA%``)."""
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base)
        return Path.home() / "AppData" / "Local"

    def temp_dir(self) -> Path:
        """Répertoire temporaire de l'utilisateur."""
        return Path(tempfile.gettempdir())
