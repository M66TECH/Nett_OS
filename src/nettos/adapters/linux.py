# SPDX-License-Identifier: AGPL-3.0-or-later
"""Adaptateur Linux : volumes montés et chemins système.

Lecture seule. Les points de montage sont lus dans ``/proc/self/mounts``,
qui ne nécessite aucun privilège, avec repli sur ``/proc/mounts``.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from nettos.adapters.base import PlatformAdapter
from nettos.core.result import VolumeInfo

_PSEUDO_FILESYSTEMS = frozenset(
    {
        "proc",
        "sysfs",
        "devtmpfs",
        "devpts",
        "tmpfs",
        "cgroup",
        "cgroup2",
        "securityfs",
        "pstore",
        "bpf",
        "debugfs",
        "tracefs",
        "hugetlbfs",
        "mqueue",
        "configfs",
        "fusectl",
        "autofs",
        "binfmt_misc",
        "rpc_pipefs",
        "nsfs",
        "squashfs",
    }
)

_MOUNT_SOURCES = ("/proc/self/mounts", "/proc/mounts")


class LinuxAdapter(PlatformAdapter):
    """Adaptateur pour les systèmes Linux."""

    @property
    def name(self) -> str:
        return "linux"

    def list_volumes(self) -> list[VolumeInfo]:
        """Retourne les volumes physiques montés, sans pseudo-systèmes."""
        volumes: list[VolumeInfo] = []
        seen: set[str] = set()

        for mount_point, filesystem in self._read_mounts():
            if filesystem in _PSEUDO_FILESYSTEMS or mount_point in seen:
                continue
            seen.add(mount_point)
            info = self._volume_info(mount_point, filesystem)
            if info is not None:
                volumes.append(info)

        volumes.sort(key=lambda v: v.mount_point)
        return volumes

    def user_cache_dir(self) -> Path:
        """Répertoire de cache utilisateur (``$XDG_CACHE_HOME``)."""
        base = os.environ.get("XDG_CACHE_HOME")
        if base:
            return Path(base)
        return Path.home() / ".cache"

    def temp_dir(self) -> Path:
        """Répertoire temporaire de l'utilisateur."""
        return Path(tempfile.gettempdir())

    def _read_mounts(self) -> list[tuple[str, str]]:
        """Retourne des couples ``(point de montage, type de système)``."""
        for source in _MOUNT_SOURCES:
            path = Path(source)
            if not path.is_file():
                continue
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            return self._parse_mounts(raw)
        return []

    @staticmethod
    def _parse_mounts(raw: str) -> list[tuple[str, str]]:
        """Analyse le format ``/proc/mounts`` (échappements octaux inclus)."""
        entries: list[tuple[str, str]] = []
        for line in raw.splitlines():
            fields = line.split()
            if len(fields) < 3:
                continue
            mount_point = _unescape_octal(fields[1])
            filesystem = fields[2]
            entries.append((mount_point, filesystem))
        return entries

    @staticmethod
    def _volume_info(mount_point: str, filesystem: str) -> VolumeInfo | None:
        try:
            usage = shutil.disk_usage(mount_point)
        except OSError:
            return None
        return VolumeInfo(
            mount_point=mount_point,
            total_bytes=usage.total,
            used_bytes=usage.used,
            free_bytes=usage.free,
            filesystem=filesystem,
        )


def _unescape_octal(value: str) -> str:
    """Décode les séquences ``\\040`` (espace) du format ``/proc/mounts``."""
    if "\\" not in value:
        return value
    result = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 3 < len(value):
            chunk = value[index + 1 : index + 4]
            try:
                result.append(int(chunk, 8))
                index += 4
                continue
            except ValueError:
                pass
        result.extend(char.encode("utf-8"))
        index += 1
    return result.decode("utf-8", errors="replace")
