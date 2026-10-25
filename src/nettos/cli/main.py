# SPDX-License-Identifier: AGPL-3.0-or-later
"""Point d'entrée de la ligne de commande NettOS.

Phase 2 : ``nettos scan`` produit un rapport complet (volumes, totaux,
répertoires les plus volumineux, erreurs classées), en texte ou en JSON.
Les commandes ``clean --dry-run`` et ``report --json`` arriveront avec les
phases correspondantes.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from nettos import __version__
from nettos.core.formatting import format_bytes
from nettos.services.scan_service import ScanService

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3
EXIT_CANCELLED = 4


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
    scan.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="Nombre de répertoires les plus volumineux affichés (défaut : 10).",
    )
    scan.add_argument(
        "--decimal",
        action="store_true",
        help="Affiche les tailles en unités décimales (ko, Mo) au lieu de binaires (Kio, Mio).",
    )
    scan.add_argument(
        "--no-volumes",
        action="store_true",
        help="N'énumère pas les volumes de la plateforme (plus rapide).",
    )
    scan.add_argument(
        "--errors",
        type=int,
        default=20,
        metavar="N",
        help="Nombre d'erreurs détaillées affichées (défaut : 20).",
    )

    rules = subparsers.add_parser(
        "rules",
        help="Liste les règles de nettoyage connues.",
        description=(
            "Liste les règles de nettoyage livrées avec l'application, leur statut "
            "et leur niveau de risque. Aucune suppression n'est effectuée."
        ),
    )
    rules.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Émet la liste au format JSON.",
    )
    rules.add_argument(
        "--all",
        action="store_true",
        dest="show_all",
        help="Affiche aussi les règles non applicables à cette plateforme.",
    )
    rules.add_argument(
        "--risk",
        choices=("low", "moderate", "high"),
        default=None,
        help="Ne garde que les règles d'un niveau de risque égal ou supérieur.",
    )

    plan = subparsers.add_parser(
        "plan",
        help="Simule le nettoyage d'une règle, sans rien supprimer.",
        description=(
            "Énumère les fichiers qu'une règle viserait. Cette commande est "
            "strictement en lecture seule : aucun fichier n'est modifié."
        ),
    )
    plan.add_argument(
        "rule",
        nargs="?",
        default=None,
        help="Identifiant de la règle (par défaut : toutes les règles actives).",
    )
    plan.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Émet le plan au format JSON.",
    )
    plan.add_argument(
        "--decimal",
        action="store_true",
        help="Affiche les tailles en unités décimales.",
    )
    plan.add_argument(
        "--limit",
        type=int,
        default=20,
        metavar="N",
        help="Nombre de fichiers affichés par règle (défaut : 20).",
    )

    return parser


def _run_scan(path: str, args: argparse.Namespace) -> int:
    root = Path(path).expanduser()
    if not root.exists() or not root.is_dir():
        print(f"nettos: répertoire introuvable : {path}", file=sys.stderr)
        return EXIT_USAGE

    root = root.resolve()
    service = ScanService()
    result = service.scan(root, include_volumes=not args.no_volumes)

    if args.as_json:
        payload = service.as_dict(result)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        _print_human_report(result, args)

    if result.status.value == "cancelled":
        return EXIT_CANCELLED
    if result.status.value == "unknown":
        return EXIT_INCOMPLETE
    return EXIT_OK


def _print_human_report(result: object, args: argparse.Namespace) -> None:
    from nettos.core.result import ScanResult

    assert isinstance(result, ScanResult)
    binary = not args.decimal

    print(f"Racine analysée : {result.root}")
    print(f"Fichiers        : {result.total_files:,}".replace(",", " "))
    print(f"Taille logique  : {format_bytes(result.total_bytes, binary=binary)}")
    if result.allocated_bytes:
        print(f"Taille allouée  : {format_bytes(result.allocated_bytes, binary=binary)}")
    print(f"Entrées vues    : {result.total_entries:,}".replace(",", " "))
    print(f"Durée           : {result.duration_seconds:.3f} s")
    print(f"Statut          : {result.status.value}")

    if result.volumes:
        print("\nVolumes :")
        for volume in result.volumes:
            used = format_bytes(volume.used_bytes, binary=binary)
            total = format_bytes(volume.total_bytes, binary=binary)
            percent = volume.used_ratio * 100
            print(f"  - {volume.mount_point:<12} {used} / {total} ({percent:.0f} %)")

    if result.directories:
        ranked = sorted(result.directories, key=lambda d: d.size_bytes, reverse=True)
        top = ranked[: max(args.top, 0)]
        print(f"\nRépertoires les plus volumineux ({len(top)}/{len(ranked)}) :")
        for entry in top:
            size = format_bytes(entry.size_bytes, binary=binary)
            print(f"  {size:>10}  {entry.file_count:>8} fichiers  {entry.path}")

    if result.errors:
        print(f"\nErreurs ({result.error_count}) :")
        for kind, count in sorted(result.error_count_by_kind.items()):
            print(f"  - {kind} : {count}")
        for error in result.errors[: max(args.errors, 0)]:
            print(f"    {error.path} : {error.reason}")


def _run_rules(args: argparse.Namespace) -> int:
    from nettos.cleaners import RiskLevel
    from nettos.services.clean_rules_service import CleanRulesService

    service = CleanRulesService()
    minimum = RiskLevel.parse(args.risk) if args.risk else None
    entries = service.list_rules(risk_at_least=minimum)

    if not args.show_all:
        entries = [
            entry for entry in entries if entry.status.value in {"active", "stale", "disabled"}
        ]

    if args.as_json:
        print(json.dumps(service.as_dict(entries), ensure_ascii=False, indent=2))
        return EXIT_OK

    platform = service.registry.platform.value
    print(f"Plateforme : {platform}")
    print(f"Règles     : {len(entries)}\n")
    for entry in entries:
        rule = entry.rule
        if rule is None:
            print(f"  [illisible] {entry.status.value}: {entry.reason}")
            continue
        flags = []
        if rule.requires_admin:
            flags.append("admin requis")
        if rule.is_stale:
            flags.append("OBSOLÈTE")
        flag_text = f" [{', '.join(flags)}]" if flags else ""
        print(f"  {rule.identifier}  ({rule.risk.label}, v{rule.version}){flag_text}")
        print(f"    {rule.title}")
        if entry.status.value != "active":
            print(f"    statut : {entry.status.value} — {entry.reason}")
    return EXIT_OK


def _run_plan(args: argparse.Namespace) -> int:
    from nettos.services.clean_rules_service import CleanRulesService

    service = CleanRulesService()
    binary = not args.decimal

    identifiers = (
        [args.rule]
        if args.rule
        else [entry.identifier for entry in service.registry.active_entries() if entry.identifier]
    )
    if not identifiers:
        print("nettos: aucune règle active sur cette plateforme.", file=sys.stderr)
        return EXIT_USAGE

    payloads: list[dict[str, object]] = []
    for identifier in identifiers:
        try:
            result = service.simulate(identifier)
        except KeyError:
            print(f"nettos: règle inconnue : {identifier}", file=sys.stderr)
            return EXIT_USAGE
        except PermissionError as exc:
            print(f"nettos: {exc}", file=sys.stderr)
            return EXIT_USAGE
        payloads.append(service.simulation_as_dict(result))
        if not args.as_json:
            _print_plan(result, binary=binary, limit=args.limit)

    if args.as_json:
        output = payloads[0] if args.rule else payloads
        print(json.dumps(output, ensure_ascii=False, indent=2))
    elif not args.as_json:
        print("\nAucune suppression effectuée : cette commande est en lecture seule.")

    return EXIT_OK


def _print_plan(result: object, *, binary: bool, limit: int) -> None:
    from nettos.cleaners.base import SimulationResult

    assert isinstance(result, SimulationResult)
    print(f"\nRègle    : {result.rule_identifier}")
    print(f"Fichiers : {result.file_count}")
    print(f"Taille   : {format_bytes(result.total_bytes, binary=binary)}")
    if result.truncated:
        print("Attention : énumération tronquée par la limite de sécurité.")
    for root in result.missing_roots:
        print(f"  racine absente : {root}")
    for candidate in result.candidates[: max(limit, 0)]:
        size = format_bytes(candidate.size_bytes, binary=binary)
        print(f"  {size:>10}  {candidate.age_days:7.1f} j  {candidate.path}")


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entrée exécutable."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan(args.path, args)
    if args.command == "rules":
        return _run_rules(args)
    if args.command == "plan":
        return _run_plan(args)

    parser.print_help()
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
