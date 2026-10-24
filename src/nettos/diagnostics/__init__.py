# SPDX-License-Identifier: AGPL-3.0-or-later
"""Moteurs de diagnostic : scanner, classifier, mesurer.

Ce paquet n'écrit jamais sur le disque (cahier des charges, section 4.1).
Il fonctionne et se teste sans interface graphique.
"""

from __future__ import annotations

from nettos.diagnostics.scanner import StorageScanner

__all__ = ["StorageScanner"]
