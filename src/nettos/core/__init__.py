# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cœur du domaine : modèles partagés, erreurs et types de résultats.

Ce paquet ne dépend ni de Qt, ni de la couche système : il doit rester
importable et testable sans interface graphique ni privilèges particuliers.
"""

from __future__ import annotations

from nettos.core.cancellation import CancellationToken
from nettos.core.errors import (
    NettOSError,
    OperationCancelledError,
    PathOutsideAuthorizedRootError,
    ScanError,
    ScanLimitExceededError,
    UnsupportedPlatformError,
)
from nettos.core.result import (
    DiagnosticStatus,
    DirectorySize,
    ErrorKind,
    ScanErrorRecord,
    ScanResult,
    VolumeInfo,
)

__all__ = [
    "CancellationToken",
    "DiagnosticStatus",
    "DirectorySize",
    "ErrorKind",
    "NettOSError",
    "OperationCancelledError",
    "PathOutsideAuthorizedRootError",
    "ScanError",
    "ScanErrorRecord",
    "ScanLimitExceededError",
    "ScanResult",
    "UnsupportedPlatformError",
    "VolumeInfo",
]
