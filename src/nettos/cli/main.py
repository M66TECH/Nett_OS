# SPDX-License-Identifier: AGPL-3.0-or-later
"""Point d'entrée de la ligne de commande NettOS.

Phase 1 : squelette avec ``scan`` en lecture seule et ``--version``.
Les commandes ``clean --dry-run`` et ``report --json`` arriveront avec
les phases correspondantes.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from nettos import __version__
from nettos.security.path_policy import resolve_no_symlinks
from nettos.services.scan_service import ScanService


def build_parser() -> argparse.ArgumentParser:
    """Construit l'analyseur d'arguments."""
    parser = argparse.ArgumentParser(
        prog="nettos",
        description=(
            "NettOS — diagnostic, maintenance et nettoyage système. "
            "Toutes les opérations de cette version sont en lecture seule."
        ),
    )
    parser.add_argument("--version", action="version", version=f"nettos {__version__}")
    parser.add_argument(
        "--lang",
        default=None,
        metavar="LANGUE",
        help="Langue des messages de ligne de commande (fr ou en).",
    )

    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser(
        "scan",
        help="Analyse une arborescence en lecture seule.",
        description="Analyse une arborescence en lecture seule et affiche les tailles.",
    )
    scan.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Répertoire à analyser (par défaut : répertoire courant).",
    )
    scan.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Émet le résultat au format JSON.",
    )

    return parser


def _run_scan(path: str, as_json: bool) -> int:
    root = Path(path).resolve()
    if not root.exists() or not root.is_dir():
        print(f"nettos: répertoire introuvable : {path}", file=sys.stderr)
        return 2

    service = ScanService()
    result = service.scan(root)

    if as_json:
        payload = service.as_dict(result)
        payload["root"] = str(resolve_no_symlinks(root, root=root))
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Racine analysée : {root}")
        print(f"Fichiers        : {result.total_files}")
        print(f"Taille totale   : {result.total_bytes} octets")
        print(f"Durée           : {result.duration_seconds:.3f} s")
        print(f"Statut          : {result.status.value}")
        if result.errors:
            print(f"Erreurs         : {result.error_count}")
            for err in result.errors:
                print(f"  - {err.path} : {err.reason}")

    return 0 if result.status.value != "unknown" else 3


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entrée exécutable."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan(args.path, args.as_json)

    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
