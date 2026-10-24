# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sécurité : validation de chemins et politique d'opérations.

Toute cible doit être validée contre une liste d'autorisation explicite
avant d'être proposée au nettoyage. Ce module ne supprime rien.
"""

from __future__ import annotations

from nettos.security.path_policy import is_within_root, resolve_no_symlinks

__all__ = ["is_within_root", "resolve_no_symlinks"]
