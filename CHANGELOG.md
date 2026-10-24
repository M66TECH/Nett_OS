# Journal des modifications

Toutes les modifications notables de ce projet sont consignées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le
projet adhère au [versionnage sémantique](https://semver.org/lang/fr/).

## [Non publié]

### À venir

- Phase 2 : scanner de stockage en lecture seule avec volumes, progression et
  annulation ; format `nettos scan --json` stabilisé.

---

## [0.1.0] — 2026-10-24

Première pierre du socle : Phase 1 du plan de développement (semaines 1 à 2).

### Ajouté

- Package Python installable `nettos` (layout `src/`, Python 3.10+).
- Modèles du domaine : `VolumeInfo`, `ScanErrorRecord`, `ScanResult`,
  `DiagnosticStatus` (`core/result.py`).
- Erreurs typées : `NettOSError`, `ScanError`, `PathOutsideAuthorizedRootError`,
  `UnsupportedPlatformError`.
- Contrat `PlatformAdapter` et sélection explicite par plateforme.
- Premier scanner de stockage en lecture seule (`diagnostics/scanner.py`) :
  parcours itératif, liens non suivis, erreurs collectées, statut partiel,
  callback de progression.
- Service applicatif `ScanService` et sérialisation JSON.
- Ligne de commande `nettos` : `--version`, `nettos scan [--json] [--lang]`.
- Contrôles de chemin `is_within_root` et `resolve_no_symlinks`.
- Interface Qt minimale (`nettos-gui`) avec traductions françaises et anglaises
  chargées depuis `ui/i18n/`.
- Tests unitaires, d'intégration et de sécurité (21 tests).
- Intégration continue GitHub Actions : lint, typage, tests Linux + Windows
  (Python 3.10 et 3.12), campagne de sécurité.
- Documentation : architecture, sécurité, registre des ADR, guide de contribution.

### Décisions

- Licence AGPL-3.0-or-later conservée (ADR-0001, écart documenté avec le
  cahier des charges).
- Python 3.10 comme version minimale (ADR-0002).
- Arborescence `src/` avec découpage par couches (ADR-0003).
