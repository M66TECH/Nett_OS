# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sélection de l'adaptateur correspondant au système courant."""

from __future__ import annotations

import sys

from nettos.adapters.base import PlatformAdapter
from nettos.core.errors import UnsupportedPlatformError


def create_adapter(name: str) -> PlatformAdapter:
    """Instancie l'adaptateur nommé (``linux`` ou ``windows``).

    La sélection est faite ici, à partir de ``sys.platform``, et nulle
    part ailleurs : c'est le point d'isolation exigé par la règle 4
    d'architecture.
    """
    if name == "linux":
        from nettos.adapters.linux import LinuxAdapter

        return LinuxAdapter()
    if name == "windows":
        from nettos.adapters.windows import WindowsAdapter

        return WindowsAdapter()
    raise UnsupportedPlatformError(f"Plateforme non prise en charge : {name}")


def current_platform_name() -> str:
    """Retourne le nom de plateforme correspondant à ``sys.platform``."""
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform.startswith("win"):
        return "windows"
    raise UnsupportedPlatformError(f"Plateforme non prise en charge : {sys.platform}")


def get_platform_adapter() -> PlatformAdapter:
    """Retourne l'adaptateur de la plateforme courante."""
    return create_adapter(current_platform_name())
