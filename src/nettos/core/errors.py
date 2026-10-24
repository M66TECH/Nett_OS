# SPDX-License-Identifier: AGPL-3.0-or-later
"""Erreurs du domaine NettOS.

Les erreurs sont des valeurs de premier ordre : elles sont signalées à
l'utilisateur et journalisées, jamais avalées silencieusement
(cahier des charges, section 10.2).
"""

from __future__ import annotations


class NettOSError(Exception):
    """Erreur de base du domaine NettOS."""


class ScanError(NettOSError):
    """Erreur rencontrée pendant l'analyse (reste non fatale pour le scan)."""


class PathOutsideAuthorizedRootError(NettOSError):
    """Un chemin résolu sort du périmètre explicitement autorisé."""


class UnsupportedPlatformError(NettOSError):
    """Le système d'exploitation courant n'a pas d'adaptateur disponible."""
