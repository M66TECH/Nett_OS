# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mise en forme des tailles pour l'affichage.

Deux familles d'unités coexistent (section 8.3) et ne doivent jamais être
confondues :

- **décimal** (ko, Mo, Go), base 1000 — usage commercial des constructeurs ;
- **binaire** (Kio, Mio, Gio), base 1024 — réalité des systèmes de fichiers.

NettOS affiche par défaut le binaire, préfixé d'un choix explicite, et rend
l'ambiguïté impossible en CLI.
"""

from __future__ import annotations

_BASE_1000 = ("o", "ko", "Mo", "Go", "To", "Po")
_BASE_1024 = ("o", "Kio", "Mio", "Gio", "Tio", "Pio")


def format_bytes(value: int, *, binary: bool = True, precision: int = 1) -> str:
    """Formate une taille en octets avec unité lisible.

    ``binary=True`` utilise les unités binaires (Kio, Mio…), sinon les
    unités décimales (ko, Mo…). Les valeurs négatives sont traitées comme
    ``0`` : une taille de stockage ne peut pas être négative.
    """
    base = 1024 if binary else 1000
    units = _BASE_1024 if binary else _BASE_1000

    amount = float(max(value, 0))
    for unit in units[:-1]:
        if amount < base:
            if unit == "o":
                return f"{int(amount)} {unit}"
            return f"{amount:.{precision}f} {unit}"
        amount /= base
    return f"{amount:.{precision}f} {units[-1]}"
