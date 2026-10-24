# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cœur du domaine : modèles partagés, erreurs et types de résultats.

Ce paquet ne dépend ni de Qt, ni de la couche système : il doit rester
importable et testable sans interface graphique ni privilèges particuliers.
"""

from __future__ import annotations

from nettos.core.errors import (
    NettOSError,
    PathOutsideAuthorizedRootError,
    ScanError,
    UnsupportedPlatformError,
)
from nettos.core.result import (
    DiagnosticStatus,
    ScanErrorRecord,
    ScanResult,
    VolumeInfo,
)

__all__ = [
    "DiagnosticStatus",
    "NettOSError",
    "PathOutsideAuthorizedRootError",
    "ScanError",
    "ScanErrorRecord",
    "ScanResult",
    "UnsupportedPlatformError",
    "VolumeInfo",
]
