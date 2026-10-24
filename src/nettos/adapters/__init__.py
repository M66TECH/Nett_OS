# SPDX-License-Identifier: AGPL-3.0-or-later
"""Adaptateurs de plateforme (Linux, Windows).

Toute différence propre à un système d'exploitation (chemins, volumes,
journaux, corbeille) est isolée ici. Le cœur ne doit jamais contenir
d'appel spécifique à un OS (cahier des charges, section 4.2, règle 4).
"""

from __future__ import annotations

from nettos.adapters.base import PlatformAdapter
from nettos.adapters.factory import get_platform_adapter

__all__ = ["PlatformAdapter", "get_platform_adapter"]
