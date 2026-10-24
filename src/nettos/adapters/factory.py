# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sélection de l'adaptateur correspondant au système courant."""

from __future__ import annotations

import sys

from nettos.adapters.base import PlatformAdapter
from nettos.core.errors import UnsupportedPlatformError


def get_platform_adapter() -> PlatformAdapter:
    """Retourne l'adaptateur de la plateforme courante.

    Les implémentations seront livrées en phase 2 ; en attendant, la
    sélection lève une erreur explicite plutôt que de renvoyer ``None``.
    """
    if sys.platform.startswith("linux"):
        raise UnsupportedPlatformError(
            "Adaptateur Linux non encore implémenté (phase 2 — scanner de stockage)."
        )
    if sys.platform.startswith("win"):
        raise UnsupportedPlatformError(
            "Adaptateur Windows non encore implémenté (phase 2 — scanner de stockage)."
        )
    raise UnsupportedPlatformError(f"Plateforme non prise en charge : {sys.platform}")
