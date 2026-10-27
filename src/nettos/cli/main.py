# SPDX-License-Identifier: AGPL-3.0-or-later
"""Point d'entrée de la ligne de commande NettOS.

Commandes disponibles :

- ``scan`` : analyse de stockage en lecture seule ;
- ``rules`` : liste des règles de nettoyage et de leur statut ;
- ``plan`` : simulation d'une règle, sans aucune suppression ;
- ``clean`` : nettoyage contrôlé ; ``--dry-run`` par défaut, ``--confirm``
  obligatoire pour agir ;
- ``quarantine`` : liste, restauration et purge de la quarantaine ;
- ``history`` : journal d'audit local.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path

from nettos import __version__
from nettos.core.formatting import format_bytes
from nettos.persistence.audit_log import AuditLog
from nettos.services.scan_service import ScanService

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3
EXIT_CANCELLED = 4
EXIT_NEEDS_CONFIRMATION = 5


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

    clean = subparsers.add_parser(
        "clean",
        help="Nettoie selon une règle ; simulation par défaut.",
        description=(
            "Nettoie les fichiers visés par une règle. Par défaut, rien n'est "
            "supprimé : ajoutez --confirm pour agir réellement. Les fichiers "
            "sont déplacés en quarantaine lorsqu'elle est possible."
        ),
    )
    clean.add_argument(
        "rule",
        nargs="?",
        default=None,
        help="Identifiant de la règle (obligatoire pour agir).",
    )
    clean.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulation seule (comportement par défaut).",
    )
    clean.add_argument(
        "--confirm",
        action="store_true",
        help="Confirmation explicite : autorise la mise en quarantaine réelle.",
    )
    clean.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Émet le rapport au format JSON.",
    )
    clean.add_argument(
        "--max-targets",
        type=int,
        default=None,
        metavar="N",
        help="Plafonne le nombre de cibles traitées.",
    )
    clean.add_argument(
        "--quarantine-dir",
        default=None,
        metavar="DOSSIER",
        help="Emplacement de la quarantaine (défaut : données utilisateur).",
    )

    quarantine = subparsers.add_parser(
        "quarantine",
        help="Liste, restaure ou purge la quarantaine.",
        description="Gère les fichiers mis en quarantaine par un nettoyage.",
    )
    quarantine.add_argument(
        "action",
        nargs="?",
        default="list",
        choices=("list", "restore", "purge"),
        help="Action à effectuer (défaut : list).",
    )
    quarantine.add_argument(
        "entry",
        nargs="?",
        default=None,
        help="Identifiant d'entrée (requis pour restore).",
    )
    quarantine.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Émet la liste au format JSON.",
    )
    quarantine.add_argument(
        "--older-than",
        type=float,
        default=None,
        metavar="JOURS",
        help="Pour purge : ne purge que les entrées plus anciennes que cet âge.",
    )
    quarantine.add_argument(
        "--yes",
        action="store_true",
        help="Pour purge : confirme la suppression des entrées de quarantaine.",
    )
    quarantine.add_argument(
        "--quarantine-dir",
        default=None,
        metavar="DOSSIER",
        help="Emplacement de la quarantaine (défaut : données utilisateur).",
    )

    history = subparsers.add_parser(
        "history",
        help="Affiche le journal d'audit local.",
        description="Liste les opérations de nettoyage consignées localement.",
    )
    history.add_argument(
        "--limit",
        type=int,
        default=20,
        metavar="N",
        help="Nombre d'opérations affichées (défaut : 20).",
    )
    history.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Émet le journal au format JSON.",
    )
    history.add_argument(
        "--purge",
        action="store_true",
        help="Purge tout le journal après confirmation par --yes.",
    )
    history.add_argument(
        "--older-than",
        type=float,
        default=None,
        metavar="JOURS",
        help="Avec --purge : ne purge que les opérations plus anciennes.",
    )
    history.add_argument(
        "--yes",
        action="store_true",
        help="Confirme la purge du journal.",
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


def _quarantine_root(override: str | None) -> Path:
    from nettos.cleaners.quarantine import default_quarantine_root

    return Path(override).expanduser() if override else default_quarantine_root()


def _run_clean(args: argparse.Namespace) -> int:
    from nettos.cleaners.quarantine import Quarantine
    from nettos.persistence.audit_log import default_audit_path
    from nettos.services.clean_rules_service import CleanRulesService
    from nettos.services.clean_service import CleanExecutionService, ExecutionMode

    if args.confirm and not args.rule:
        print("nettos: --confirm exige de nommer une règle.", file=sys.stderr)
        return EXIT_USAGE

    service = CleanRulesService()
    identifiers = (
        [args.rule]
        if args.rule
        else [e.identifier for e in service.registry.active_entries() if e.identifier]
    )
    if not identifiers:
        print("nettos: aucune règle active sur cette plateforme.", file=sys.stderr)
        return EXIT_USAGE

    mode = ExecutionMode.EXECUTE if args.confirm else ExecutionMode.DRY_RUN
    quarantine = Quarantine(_quarantine_root(args.quarantine_dir))
    audit = _open_audit(default_audit_path())
    reports: list[object] = []
    exit_code = EXIT_OK

    try:
        executor = CleanExecutionService(quarantine=quarantine, audit=audit)
        for identifier in identifiers:
            try:
                cleaner = service.registry.instantiate(identifier)
            except KeyError:
                print(f"nettos: règle inconnue : {identifier}", file=sys.stderr)
                return EXIT_USAGE
            except PermissionError as exc:
                print(f"nettos: {exc}", file=sys.stderr)
                return EXIT_USAGE

            if mode is ExecutionMode.EXECUTE and not _preview_for_confirmation(cleaner, args):
                return EXIT_USAGE

            report = executor.execute(
                cleaner,
                mode=mode,
                confirm=args.confirm,
                max_targets=args.max_targets or executor.MAX_TARGETS_DEFAULT,
            )
            reports.append(report)

            if not args.as_json:
                _print_execution_report(report)
            if report.status == "needs_confirmation":
                exit_code = EXIT_NEEDS_CONFIRMATION
    finally:
        if audit is not None:
            audit.close()

    if args.as_json:
        payload = [_report_as_dict(report) for report in reports]
        print(json.dumps(payload[0] if args.rule else payload, ensure_ascii=False, indent=2))

    return exit_code


def _preview_for_confirmation(cleaner: object, args: argparse.Namespace) -> bool:
    """Affiche l'aperçu avant action : taille, risques, irréversibilité."""
    from nettos.cleaners.base import BaseCleaner

    assert isinstance(cleaner, BaseCleaner)
    result = cleaner.simulate()
    binary = True
    rule = cleaner.rule
    print(f"Règle    : {rule.identifier} (risque {rule.risk.label})")
    print(f"Fichiers : {result.file_count}")
    print(f"Taille   : {format_bytes(result.total_bytes, binary=binary)}")
    if rule.risk.requires_extra_confirmation:
        print("Attention : niveau de risque élevé.")
    if rule.reconstructed_cost:
        print(f"Reconstruction : {rule.reconstructed_cost}")
    print(f"Quarantaine : {_quarantine_root(args.quarantine_dir)}")
    return True


def _print_execution_report(report: object) -> None:
    from nettos.services.clean_service import ExecutionReport

    assert isinstance(report, ExecutionReport)
    binary = True
    print(f"\nRègle          : {report.rule_identifier}")
    print(f"Mode           : {report.mode.value}")
    print(f"Statut         : {report.status}")
    print(f"Estimation     : {format_bytes(report.theoretical_bytes, binary=binary)}")
    print(f"Récupéré       : {format_bytes(report.reclaimed_bytes, binary=binary)}")
    print(f"Traités        : {report.processed}")
    print(f"En quarantaine : {report.quarantined}")
    print(f"Irréversibles  : {report.irreversible}")
    print(f"Refusés        : {report.rejected}")
    print(f"Échecs         : {report.failed}")
    if report.error_summary:
        details = ", ".join(f"{k}={v}" for k, v in sorted(report.error_summary.items()))
        print(f"Erreurs        : {details}")
    if report.mode.value == "dry-run":
        print("\nAucune modification : mode simulation.")
    elif report.status == "needs_confirmation":
        print("\nAucune modification : ajoutez --confirm pour agir réellement.")


def _report_as_dict(report: object) -> dict[str, object]:
    from nettos.services.clean_service import ExecutionReport

    assert isinstance(report, ExecutionReport)
    return {
        "schema": "nettos.clean/1",
        "operation_id": report.operation_id,
        "rule": report.rule_identifier,
        "rule_version": report.rule_version,
        "mode": report.mode.value,
        "status": report.status,
        "theoretical_bytes": report.theoretical_bytes,
        "reclaimed_bytes": report.reclaimed_bytes,
        "processed": report.processed,
        "quarantined": report.quarantined,
        "irreversible": report.irreversible,
        "rejected": report.rejected,
        "failed": report.failed,
        "error_summary": report.error_summary,
        "duration_seconds": round(report.duration_seconds, 3),
        "targets": [
            {
                "path": item.path,
                "outcome": item.outcome.value,
                "reason": item.reason,
                "size_bytes": item.size_bytes,
            }
            for item in report.results
        ],
    }


def _open_audit(path: Path) -> AuditLog | None:
    """Ouvre le journal d'audit ; son indisponibilité ne bloque pas l'action."""
    try:
        from nettos.persistence.audit_log import AuditLog

        return AuditLog(path)
    except (OSError, sqlite3.Error) as exc:
        print(f"nettos: journal d'audit indisponible ({exc})", file=sys.stderr)
        return None


def _run_quarantine(args: argparse.Namespace) -> int:
    from nettos.cleaners.quarantine import Quarantine

    quarantine = Quarantine(_quarantine_root(args.quarantine_dir))

    if args.action == "list":
        entries = quarantine.entries()
        if args.as_json:
            print(json.dumps([e.as_dict() for e in entries], ensure_ascii=False, indent=2))
            return EXIT_OK
        if not entries:
            print("Quarantaine vide.")
            return EXIT_OK
        print(f"Quarantaine : {quarantine.root}")
        print(f"Entrées     : {len(entries)}\n")
        for entry in entries:
            size = format_bytes(entry.size_bytes)
            state = entry.state if entry.reversible else "supprimé (irréversible)"
            print(f"  {entry.entry_id}  {size:>10}  {state}")
            print(f"    {entry.original_path}")
        return EXIT_OK

    if args.action == "restore":
        if not args.entry:
            print("nettos: identifiant d'entrée requis.", file=sys.stderr)
            return EXIT_USAGE
        try:
            destination = quarantine.restore(args.entry)
        except (FileNotFoundError, FileExistsError, OSError) as exc:
            print(f"nettos: restauration impossible : {exc}", file=sys.stderr)
            return EXIT_USAGE
        print(f"Restauré : {destination}")
        return EXIT_OK

    if args.action == "purge":
        if not args.yes:
            count = len(quarantine.entries())
            print(
                f"nettos: la purge supprimerait définitivement {count} entrée(s). "
                "Ajoutez --yes pour confirmer.",
                file=sys.stderr,
            )
            return EXIT_NEEDS_CONFIRMATION
        report = quarantine.purge(older_than_days=args.older_than)
        print(
            f"Purge : {report.removed_entries} entrée(s), "
            f"{format_bytes(report.removed_bytes)} définitivement supprimés."
        )
        for failure in report.failed:
            print(f"  échec : {failure}", file=sys.stderr)
        return EXIT_OK

    print("nettos: action de quarantaine inconnue.", file=sys.stderr)
    return EXIT_USAGE


def _run_history(args: argparse.Namespace) -> int:
    from nettos.persistence.audit_log import default_audit_path

    audit = _open_audit(default_audit_path())
    if audit is None:
        return EXIT_USAGE
    try:
        if args.purge:
            if not args.yes:
                print(
                    "nettos: la purge du journal est définitive. Ajoutez --yes.",
                    file=sys.stderr,
                )
                return EXIT_NEEDS_CONFIRMATION
            removed = audit.purge(older_than_days=args.older_than)
            print(f"Journal purgé : {removed} opération(s) supprimée(s).")
            return EXIT_OK

        operations = audit.operations(limit=args.limit)
        if args.as_json:
            payload = [
                {
                    "operation_id": op.operation_id,
                    "started_at": op.started_at,
                    "finished_at": op.finished_at,
                    "rule": op.rule_identifier,
                    "rule_version": op.rule_version,
                    "mode": op.mode,
                    "status": op.status,
                    "targets": op.targets,
                    "processed": op.processed,
                    "quarantined": op.quarantined,
                    "failed": op.failed,
                    "theoretical_bytes": op.theoretical_bytes,
                    "reclaimed_bytes": op.reclaimed_bytes,
                    "error_summary": op.error_summary,
                }
                for op in operations
            ]
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return EXIT_OK

        if not operations:
            print("Journal vide.")
            return EXIT_OK
        print(f"Journal : {audit.path}\n")
        for op in operations:
            print(f"  {op.started_at}  {op.rule_identifier}  [{op.mode}] {op.status}")
            print(
                f"    traités={op.processed} quarantaine={op.quarantined} "
                f"échecs={op.failed} récupéré={format_bytes(op.reclaimed_bytes)}"
            )
        return EXIT_OK
    finally:
        audit.close()


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
    if args.command == "clean":
        return _run_clean(args)
    if args.command == "quarantine":
        return _run_quarantine(args)
    if args.command == "history":
        return _run_history(args)

    parser.print_help()
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
